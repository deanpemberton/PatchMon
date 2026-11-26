package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	hostctx "github.com/PatchMon/PatchMon/server-source-code/internal/context"
	"github.com/PatchMon/PatchMon/server-source-code/internal/middleware"
	"github.com/PatchMon/PatchMon/server-source-code/internal/remediation"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// These endpoints use the existing authenticated patch-policy permissions.
// Signed evidence alone is never an authorization to run a patch.
func (h *PatchingHandler) GetRemediationPolicy(w http.ResponseWriter, r *http.Request) {
	d := hostctx.DBFromContext(r.Context())
	if d == nil {
		JSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Database unavailable"})
		return
	}
	id := chi.URLParam(r, "id")
	if !isValidPatchUUID(id) {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid policy ID"})
		return
	}
	c, err := remediation.ReadConfiguration(r.Context(), d, id)
	if errors.Is(err, pgx.ErrNoRows) {
		JSON(w, http.StatusNotFound, map[string]string{"error": "Policy not found"})
		return
	}
	if err != nil {
		h.log.Error("remediation: read policy", "error", err)
		JSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to read remediation policy"})
		return
	}
	JSON(w, http.StatusOK, map[string]any{"configuration": c, "execution_enabled": remediation.ExecutionEnabled()})
}

func (h *PatchingHandler) PutRemediationPolicy(w http.ResponseWriter, r *http.Request) {
	d := hostctx.DBFromContext(r.Context())
	if d == nil {
		JSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Database unavailable"})
		return
	}
	id := chi.URLParam(r, "id")
	if !isValidPatchUUID(id) {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid policy ID"})
		return
	}
	actor, _ := r.Context().Value(middleware.UserIDKey).(string)
	if actor == "" {
		JSON(w, http.StatusUnauthorized, map[string]string{"error": "Authenticated user required"})
		return
	}
	var body struct {
		Revision              int64              `json:"revision"`
		Policy                remediation.Policy `json:"policy"`
		ConfirmAutomatic      bool               `json:"confirm_automatic"`
		ConfirmRecoveryWaiver bool               `json:"confirm_recovery_waiver"`
		ConfirmBackupOnly     bool               `json:"confirm_backup_only"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid remediation policy"})
		return
	}
	// Do not trust an expiry supplied by the caller. Only a new explicit
	// browser authorization creates a server-timed, one-hour window.
	body.Policy.RecoveryWaiverUntil = nil
	body.Policy.BackupOnlyHostIDs = nil
	if body.ConfirmBackupOnly {
		if body.ConfirmRecoveryWaiver || body.Policy.Mode != remediation.ModeAutomatic || !body.ConfirmAutomatic || !remediation.ExecutionEnabled() {
			JSON(w, http.StatusBadRequest, map[string]string{"error": "Backup-only risk acceptance requires explicit automatic confirmation and server opt-in; it cannot be combined with a timed waiver"})
			return
		}
		ids, err := remediation.BackupOnlyScope(r.Context(), d, id)
		if err != nil {
			JSON(w, http.StatusBadRequest, map[string]string{"error": "Unable to capture a bounded effective policy scope"})
			return
		}
		body.Policy.BackupOnlyHostIDs = ids
	}
	if body.ConfirmRecoveryWaiver {
		if body.Policy.Mode != remediation.ModeAutomatic || !body.ConfirmAutomatic || !remediation.ExecutionEnabled() {
			JSON(w, http.StatusBadRequest, map[string]string{"error": "Recovery waiver requires explicit automatic execution confirmation"})
			return
		}
		until := time.Now().UTC().Add(remediation.RecoveryWaiverDuration)
		body.Policy.RecoveryWaiverUntil = &until
	}
	if err := body.Policy.Validate(); err != nil {
		JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Policy.Mode == remediation.ModeAutomatic && (!body.ConfirmAutomatic || !remediation.ExecutionEnabled()) {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "Automatic execution requires explicit confirmation and server opt-in"})
		return
	}
	for _, hostID := range body.Policy.CanaryHostIDs {
		scope, err := remediation.ResolvePolicy(r.Context(), d, hostID)
		if err != nil {
			JSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to validate canary scope"})
			return
		}
		if scope != id {
			JSON(w, http.StatusBadRequest, map[string]string{"error": "Canary is not in the effective policy scope"})
			return
		}
	}
	if err := remediation.WriteConfiguration(r.Context(), d, id, actor, body.Revision, body.Policy); err != nil {
		if errors.Is(err, remediation.ErrRevision) {
			JSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			JSON(w, http.StatusNotFound, map[string]string{"error": "Policy not found"})
			return
		}
		if errors.Is(err, remediation.ErrImmediateRequired) || errors.Is(err, remediation.ErrRecoveryWaiverScope) || errors.Is(err, remediation.ErrBackupOnlyScope) {
			JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h.log.Error("remediation: save policy", "error", err)
		JSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to save remediation policy"})
		return
	}
	h.GetRemediationPolicy(w, r)
}
