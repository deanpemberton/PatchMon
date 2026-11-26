package queue

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/remediation"
	"github.com/PatchMon/PatchMon/server-source-code/internal/store"
	"github.com/google/uuid"
)

// processRemediation uses the native PatchMon run store and patch queue. It is
// called from the existing one-minute dispatcher, not a new unauthenticated API.
func (h *AutoPatchDispatchHandler) processRemediation(ctx context.Context) error {
	configs, err := remediation.ListConfigurations(ctx, h.db)
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	e, evidenceErr := remediation.Read(now)
	// Serialize dispatch across scheduler retries/server instances. The
	// transaction is only a lease; native run creation remains transactional.
	lock, err := h.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Rollback(context.WithoutCancel(ctx)) }()
	var locked bool
	if err = lock.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(79301826)").Scan(&locked); err != nil || !locked {
		return err
	}
	for _, c := range configs {
		r := remediation.Report{EvaluatedAt: now, Mode: c.Policy.Mode, EvidenceAvailable: evidenceErr == nil, ExecutionEnabled: remediation.ExecutionEnabled(), Hosts: []remediation.HostReport{}}
		if evidenceErr != nil {
			r.Reason = "missing, invalid or stale signed evidence"
			if err = remediation.SaveReport(ctx, h.db, c, r); err != nil {
				return err
			}
			continue
		}
		hostIDs, err := h.policies.ListTargetHostIDs(ctx, c.PolicyID)
		if err != nil {
			return err
		}
		if err = remediation.ExpirePriorityValidations(ctx, h.db, c, e, now); err != nil {
			return err
		}
		// Prioritize hosts with urgent available candidates, not static canaries.
		sort.Slice(hostIDs, func(i, j int) bool {
			if c.Policy.PriorityOnly {
				a, b := remediation.HostPriority(e, hostIDs[i]), remediation.HostPriority(e, hostIDs[j])
				if a != b {
					return a < b
				}
				return hostIDs[i] < hostIDs[j]
			}
			a, b := slices.Contains(c.Policy.CanaryHostIDs, hostIDs[i]), slices.Contains(c.Policy.CanaryHostIDs, hostIDs[j])
			if a != b {
				return a
			}
			return hostIDs[i] < hostIDs[j]
		})
		for _, hostID := range hostIDs {
			row := remediation.HostReport{HostID: hostID}
			if err = h.evaluateRemediationHost(ctx, c, e, now, &row); err != nil {
				// A database/queue failure never silently degrades to execution.
				h.log.Warn("remediation: evaluation blocked", "policy_id", c.PolicyID, "host_id", hostID, "error", err)
				row.Blocker = "evaluation_error"
			}
			r.Hosts = append(r.Hosts, row)
		}
		if err = remediation.SaveReport(ctx, h.db, c, r); err != nil {
			return err
		}
	}
	return nil
}

func (h *AutoPatchDispatchHandler) evaluateRemediationHost(ctx context.Context, c remediation.Configuration, e remediation.Evidence, now time.Time, row *remediation.HostReport) error {
	if c.DelayType != "immediate" {
		row.Blocker = "native_policy_not_immediate"
		return nil
	}
	hostID := row.HostID
	id, err := remediation.ResolvePolicy(ctx, h.db, hostID)
	if err != nil {
		return err
	}
	effective, err := h.policies.ResolveEffectivePolicy(ctx, hostID)
	if err != nil {
		return err
	}
	if id != c.PolicyID || effective == nil || effective.ID != id {
		row.Blocker = "outside_effective_policy"
		return nil
	}
	ev, ok := remediation.FindHost(e, hostID)
	if !ok {
		row.Blocker = "missing_host_evidence"
		return nil
	}
	row.UnclassifiedSecurityUpdates = ev.UnclassifiedSecurityUpdates
	if !remediation.Fresh(ev.ObservedAt, now, remediation.MaxEvidenceAge) {
		row.Blocker = "stale_host_evidence"
		return nil
	}
	if err = remediation.CheckEvidenceIdentity(ctx, h.db, ev, now); err != nil {
		row.Blocker = err.Error()
		return nil
	}
	last, err := remediation.LastRoutine(ctx, h.db, c.PolicyID, hostID)
	if err != nil {
		return err
	}
	row.Decisions, err = remediation.Observe(ctx, h.db, c, ev, now, last)
	if err != nil {
		return err
	}
	if c.Policy.Mode == remediation.ModeShadow {
		row.Blocker = "shadow_mode"
		return nil
	}
	if c.Policy.Mode == remediation.ModeAutomatic && !remediation.ExecutionEnabled() {
		row.Blocker = "execution_not_enabled"
		return nil
	}
	host, err := h.hosts.GetByID(ctx, hostID)
	if err != nil {
		return err
	}
	if host == nil {
		row.Blocker = "host_missing"
		return nil
	}
	agentVersion := ""
	if host.AgentVersion != nil {
		agentVersion = *host.AgentVersion
	}
	s, err := remediation.MakeSnapshotForAgent(c, ev, row.Decisions, agentVersion)
	if err != nil {
		row.Blocker = "no_unambiguous_eligible_packages"
		return nil
	}
	s, err = remediation.ExpandPriorityDependencies(ctx, h.db, c, ev, s, row.Decisions, agentVersion, now)
	if err != nil {
		return err
	}
	if err = remediation.CheckHost(ctx, h.db, ev, s.Packages, now, c.Policy); err != nil {
		row.Blocker = err.Error()
		return nil
	}
	if c.Policy.Mode == remediation.ModeAutomatic && !c.Policy.PriorityOnly {
		passed, err := remediation.CanaryPassed(ctx, h.db, c, e, s, now)
		if err != nil {
			return err
		}
		if !passed {
			row.Blocker = "awaiting_verified_canary"
			return nil
		}
	}
	previous, err := remediation.LatestAttempt(ctx, h.db, s)
	if err != nil {
		return err
	}
	if previous != "" {
		run, err := h.patchRuns.GetByID(ctx, previous)
		if err != nil {
			return err
		}
		if run == nil {
			return errors.New("attempt vanished")
		}
		row.RunID = run.ID
		if c.Policy.PriorityOnly && run.CompletedAt.Valid && now.Sub(run.CompletedAt.Time) >= 30*time.Minute &&
			(run.Status == "failed" || run.Status == "timed_out" ||
				(run.Status == "cancelled" && run.DryRun && run.ErrorMessage != nil && *run.ErrorMessage == "Priority validation expired or changed")) {
			// A terminal failed attempt may be revalidated against current
			// inventory, backup evidence and the same explicit policy.
			row.RunID = ""
		} else {
			if run.Status != "validated" || !run.DryRun {
				row.Blocker = "existing_attempt_" + run.Status
				return nil
			}
			if c.Policy.Mode != remediation.ModeAutomatic {
				row.Blocker = "awaiting_browser_approval"
				return nil
			}
			if err = remediation.ValidateDryRun(run, s, now); err != nil {
				row.Blocker = "validation_expired_or_unsafe"
				return nil
			}
			// Transactional native approval: no manufactured user/session/token.
			if _, err = remediation.Recheck(ctx, h.db, s, now, true); err != nil {
				row.Blocker = err.Error()
				return nil
			}
			raw, err := json.Marshal(s)
			if err != nil {
				return err
			}
			newID := uuid.New().String()
			task, err := NewRunPatchTask(RunPatchPayload{HostID: hostID, ApiID: host.ApiID, PatchRunID: newID, PatchType: "patch_package", PackageNames: s.Names()})
			if err != nil {
				return err
			}
			if err = h.patchRuns.ApproveAndCreateRun(ctx, run.ID, nil, newID, hostID, "patch-run-"+newID, "patch_package", nil, s.Names(), nil, nil, &c.PolicyID, &c.Name, raw, nil); err != nil {
				return err
			}
			if _, err = h.queueClient.Enqueue(task); err != nil {
				_, _ = h.patchRuns.Cancel(context.WithoutCancel(ctx), newID, "Failed to queue remediation")
				return err
			}
			row.RunID = newID
			return nil
		}
	}
	// Native unique active-run index is the last line of defence. Include
	// scheduled/disconnected/validated runs in the fleet concurrency limit.
	active, err := remediation.ActiveCount(ctx, h.db, c.PolicyID)
	if err != nil {
		return err
	}
	total, err := remediation.ActiveCount(ctx, h.db, "")
	if err != nil {
		return err
	}
	if active >= c.Policy.MaxConcurrent || total >= 5 {
		row.Blocker = "concurrency_limit"
		return nil
	}
	if c.Policy.Mode == remediation.ModeAutomatic && !c.Policy.PriorityOnly && slices.Contains(c.Policy.CanaryHostIDs, hostID) && active > 0 {
		row.Blocker = "canary_serial_limit"
		return nil
	}
	if _, err = remediation.Recheck(ctx, h.db, s, now, false); err != nil {
		row.Blocker = err.Error()
		return nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	runID := uuid.New().String()
	task, err := NewRunPatchTask(RunPatchPayload{HostID: hostID, ApiID: host.ApiID, PatchRunID: runID, PatchType: "patch_package", PackageNames: s.Names(), DryRun: true})
	if err != nil {
		return err
	}
	if _, err = h.patchRuns.CreateRun(ctx, runID, hostID, "patch-run-"+runID, "patch_package", nil, s.Names(), nil, true, nil, &c.PolicyID, &c.Name, raw, nil); err != nil {
		if errors.Is(err, store.ErrHostHasActivePatchRun) {
			row.Blocker = "host_has_active_run"
			return nil
		}
		return err
	}
	if _, err = h.queueClient.Enqueue(task); err != nil {
		_, _ = h.patchRuns.Cancel(context.WithoutCancel(ctx), runID, "Failed to queue remediation validation")
		return err
	}
	row.RunID = runID
	return nil
}
