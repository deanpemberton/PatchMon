import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { useConfirm } from "../../contexts/ConfirmContext";
import { useToast } from "../../contexts/ToastContext";
import api from "../../utils/api";
import CveLink from "../ui/CveLink";

const modes = [
	["disabled", "Disabled"],
	["shadow", "Shadow — evaluate only"],
	["approval", "Require browser approval"],
	["automatic", "Automatic — validated canary first"],
];

function PolicyEditor({ configuration, executionEnabled, hosts, refresh }) {
	const { canManagePatching } = useAuth();
	const canEdit = canManagePatching();
	const confirm = useConfirm();
	const toast = useToast();
	const prefix = useId();
	const [form, setForm] = useState(configuration.policy);
	const [waiveRecovery, setWaiveRecovery] = useState(false);
	const [acceptBackupOnly, setAcceptBackupOnly] = useState(
		(configuration.policy.backup_only_host_ids || []).length > 0,
	);
	const canWaiveRecovery =
		form.mode === "automatic" &&
		form.max_concurrent === 1 &&
		(form.canary_host_ids || []).length === 1;
	const mutation = useMutation({
		mutationFn: (confirmed) =>
			api.put(`/patching/policies/${configuration.policy_id}/remediation`, {
				revision: configuration.revision,
				policy: {
					...form,
					recovery_waiver_until: undefined,
					backup_only_host_ids: undefined,
				},
				confirm_automatic: confirmed,
				confirm_recovery_waiver: canWaiveRecovery && waiveRecovery,
				confirm_backup_only: form.mode === "automatic" && acceptBackupOnly,
			}),
		onSuccess: () => {
			toast.success("Remediation policy saved");
			refresh();
		},
		onError: (err) => toast.error(err.response?.data?.error || err.message),
	});
	const change = (key, value) => setForm((old) => ({ ...old, [key]: value }));
	const save = async (event) => {
		event.preventDefault();
		let confirmed = false;
		if (form.mode === "automatic") {
			confirmed = await confirm({
				title: "Authorize automatic remediation",
				message:
					canWaiveRecovery && waiveRecovery
						? "Authorize a single directly assigned canary for one hour without a tested restore. A complete recent backup, health checks, signed evidence and version-pinned validation remain mandatory. Recovery may fail. No automatic reboot."
						: acceptBackupOnly
							? "Accept the risk of an untested restore for the currently assigned, non-excluded hosts. Each upgrade still requires a current complete backup, signed fix evidence, health checks, exact validation and canary gates. New hosts do not inherit this exception. No automatic reboot."
							: "This policy authorizes unattended, version-pinned package upgrades for its effective host scope. Backups, validation and canaries are required. No automatic reboot is permitted.",
				confirmLabel: "Authorize automatic remediation",
			});
			if (!confirmed) return;
		}
		mutation.mutate(confirmed);
	};
	const fields = [
		["critical_hours", "Critical / known exploited (hours)", 1, 168],
		["high_hours", "High (hours)", 1, 720],
		["routine_hours", "Routine interval (hours)", 1, 720],
		["max_concurrent", "Maximum concurrent hosts", 1, 5],
		["backup_max_age_hours", "Maximum backup age (hours)", 1, 72],
	];
	return (
		<form onSubmit={save} className="space-y-3">
			<p className="text-sm text-secondary-600 dark:text-secondary-300">
				{configuration.priority_only
					? "Priority-only: CVE severity sets urgency. Available APT updates are version-pinned and validated; no application-health or canary gate and no claim that installation fixes a CVE. A current complete backup and authorized scope are required."
					: "Requires an immediate policy, signed fix evidence, a complete backup, verified recovery or explicit acceptance, health checks and a compatible APT agent."}
			</p>
			<label htmlFor={`${prefix}-mode`} className="block text-sm font-medium">
				Execution mode
			</label>
			<select
				id={`${prefix}-mode`}
				className="w-full rounded border border-secondary-300 dark:border-secondary-600 bg-white dark:bg-secondary-700 text-secondary-900 dark:text-white px-3 py-2 disabled:opacity-60 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
				value={form.mode}
				disabled={!canEdit}
				onChange={(event) => change("mode", event.target.value)}
			>
				{modes.map(([value, label]) => (
					<option
						key={value}
						value={value}
						disabled={value === "automatic" && !executionEnabled}
					>
						{configuration.priority_only && value === "automatic"
							? "Automatic — package priority"
							: label}
					</option>
				))}
			</select>
			{!executionEnabled && (
				<p className="text-sm text-amber-700 dark:text-amber-300">
					Server execution switch is off. No managed upgrade can execute.
				</p>
			)}
			<div className="grid grid-cols-1 gap-3 md:grid-cols-2">
				{fields.map(([key, label, min, max]) => (
					<div key={key}>
						<label htmlFor={prefix + key} className="block text-sm">
							{label}
						</label>
						<input
							id={prefix + key}
							className="w-full rounded border border-secondary-300 dark:border-secondary-600 bg-white dark:bg-secondary-700 text-secondary-900 dark:text-white px-3 py-2 disabled:opacity-60 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
							type="number"
							min={min}
							max={max}
							required
							disabled={!canEdit}
							value={form[key]}
							onChange={(event) => change(key, Number(event.target.value))}
						/>
					</div>
				))}
			</div>
			<fieldset>
				<legend className="text-sm font-medium">
					{configuration.priority_only
						? "Canary preferences (not required for priority-only execution)"
						: "Canary hosts (must belong to this policy)"}
				</legend>
				<div className="max-h-40 overflow-auto space-y-1">
					{hosts.map((host) => (
						<label key={host.id} className="flex items-center gap-2 text-sm">
							<input
								type="checkbox"
								disabled={!canEdit}
								checked={(form.canary_host_ids || []).includes(host.id)}
								onChange={(event) =>
									change(
										"canary_host_ids",
										event.target.checked
											? [...(form.canary_host_ids || []), host.id]
											: (form.canary_host_ids || []).filter(
													(id) => id !== host.id,
												),
									)
								}
							/>
							{host.friendly_name || host.hostname || host.id}
						</label>
					))}
				</div>
			</fieldset>
			{configuration.policy.recovery_waiver_until && (
				<p className="text-sm text-amber-700 dark:text-amber-300">
					Recovery waiver expires at{" "}
					{new Date(
						configuration.policy.recovery_waiver_until,
					).toLocaleString()}
					. Execution is blocked after expiry.
				</p>
			)}
			{form.mode === "automatic" && (
				<label className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300">
					<input
						type="checkbox"
						disabled={!canEdit}
						checked={acceptBackupOnly}
						onChange={(event) => {
							setAcceptBackupOnly(event.target.checked);
							if (event.target.checked) setWaiveRecovery(false);
						}}
					/>
					Accept current complete backups without tested restores for this
					policy's currently assigned, non-excluded hosts. Recovery may fail.
				</label>
			)}
			{canWaiveRecovery && !acceptBackupOnly && (
				<label className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300">
					<input
						type="checkbox"
						disabled={!canEdit}
						checked={waiveRecovery}
						onChange={(event) => setWaiveRecovery(event.target.checked)}
					/>
					Allow this directly assigned canary to run for one hour without a
					tested restore. A current complete backup is still required.
				</label>
			)}
			{canEdit && (
				<button
					type="submit"
					disabled={mutation.isPending}
					className="btn-primary"
				>
					Save remediation policy
				</button>
			)}
		</form>
	);
}

export default function RemediationPolicy({ policy, hosts }) {
	const queryClient = useQueryClient();
	const queryKey = ["patch-remediation", policy.id];
	const { data, isLoading, isError } = useQuery({
		queryKey,
		queryFn: () =>
			api
				.get(`/patching/policies/${policy.id}/remediation`)
				.then((res) => res.data),
		refetchInterval: 60000,
	});
	if (isLoading)
		return <p className="p-4 text-sm">Loading remediation policy...</p>;
	if (isError || !data?.configuration)
		return (
			<p className="p-4 text-sm text-amber-700 dark:text-amber-300">
				Remediation settings unavailable.
			</p>
		);
	const configuration = data.configuration;
	const report = configuration.report;
	const hostName = (id) => {
		const host = hosts.find((item) => item.id === id);
		return host?.friendly_name || host?.hostname || id;
	};
	const unclassified = (report?.hosts || []).flatMap((host) =>
		(host.unclassified_security_updates || []).map((name) => ({
			host: host.host_id,
			name,
		})),
	);
	const decisions = (report?.hosts || []).flatMap((host) =>
		(host.decisions || []).map((decision) => ({
			...decision,
			host: host.host_id,
			blocker: host.blocker,
		})),
	);
	return (
		<section className="border-t border-secondary-200 dark:border-secondary-700 p-4 space-y-4">
			<h3 className="font-semibold">Severity-based remediation</h3>
			<PolicyEditor
				key={configuration.revision}
				configuration={configuration}
				executionEnabled={data.execution_enabled}
				hosts={hosts}
				refresh={() => {
					queryClient.invalidateQueries({ queryKey });
					queryClient.invalidateQueries({ queryKey: ["patching-policies"] });
				}}
			/>
			{report && (
				<div className="space-y-2">
					<h4 className="font-semibold text-sm">Latest evaluation</h4>
					<p className="text-sm">
						Open: {report.open_findings} · Overdue: {report.overdue_findings} ·
						Unobserved: {report.unobserved_findings}
					</p>
					<p className="text-xs text-secondary-600 dark:text-secondary-300">
						{new Date(report.evaluated_at).toLocaleString()} ·{" "}
						{report.reason ||
							(report.evidence_available
								? "Signed evidence available"
								: "Evidence unavailable")}
					</p>
					{unclassified.length > 0 && (
						<details className="text-sm text-amber-700 dark:text-amber-300">
							<summary>
								{unclassified.length} unclassified security updates (manual
								review)
							</summary>
							<ul className="max-h-40 overflow-auto">
								{unclassified.slice(0, 500).map((item) => (
									<li key={`${item.host}:${item.name}`}>
										{hostName(item.host)}: {item.name}
									</li>
								))}
							</ul>
						</details>
					)}
					<div className="max-h-80 overflow-auto">
						<table className="min-w-full text-xs">
							<thead>
								<tr>
									{[
										"Host",
										"Package",
										"CVE",
										"CVSS",
										"Priority",
										"Deadline",
										"Decision",
									].map((label) => (
										<th key={label} scope="col" className="text-left p-2">
											{label}
										</th>
									))}
								</tr>
							</thead>
							<tbody>
								{decisions.slice(0, 500).map((row) => (
									<tr
										key={`${row.host}:${row.target.package}:${row.target.cve || row.target.candidate}`}
										className="border-t border-secondary-200 dark:border-secondary-700"
									>
										<td className="p-2">{hostName(row.host)}</td>
										<td className="p-2">{row.target.package}</td>
										<td className="p-2">
											<CveLink cve={row.target.cve} />
										</td>
										<td className="p-2" title={row.target.score_source || ""}>
											{row.target.score ?? "Unknown"}
										</td>
										<td className="p-2">{row.severity}</td>
										<td className="p-2">
											{row.deadline
												? new Date(row.deadline).toLocaleString()
												: "Review"}
											{row.overdue && " (overdue)"}
										</td>
										<td className="p-2">{row.blocker || row.reason}</td>
									</tr>
								))}
							</tbody>
						</table>
						{decisions.length > 500 && (
							<p className="text-xs">Showing first 500 decisions.</p>
						)}
					</div>
				</div>
			)}
		</section>
	);
}
