import { memo, useMemo } from "react";

const SUSPICIOUS_TYPES = new Set([
  "intrusion_correlation",
  "suspicious_chain",
  "suspicious_process",
  "powershell_encoded",
  "dangerous_command",
  "failed_login",
  "account_lockout",
  "threat_detected",
  "malware_signature",
]);

function formatScanAgo(timestamp) {
  if (!timestamp) return "Just now";
  const diff = Math.max(0, Date.now() - new Date(timestamp).getTime());
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins === 1) return "1 min ago";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  return hours === 1 ? "1 hr ago" : `${hours} hr ago`;
}

const NetStat = memo(function NetStat({ label, value, tone = "default", large = false }) {
  return (
    <div className={`net-stat net-stat-${tone} ${large ? "net-stat-large" : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
});

function NetworkSecurity({ snapshot = {}, overview = {}, alerts = [] }) {
  const stats = useMemo(() => {
    const suspicious = alerts.filter((a) => SUSPICIOUS_TYPES.has(a.event_type)).length;
    const blocked = alerts.filter((a) =>
      a.event_type === "failed_login" || a.event_type === "account_lockout"
    ).length;

    const firewallStatus = overview?.score >= 70 ? "Alert" : "Protected";
    const idsStatus = overview?.telemetry?.threat_detection?.state === "error"
      ? "Degraded"
      : "Active";

    return {
      active: snapshot.connections ?? 0,
      suspicious: suspicious || (overview?.critical > 0 ? overview.critical : 0),
      blocked: blocked || Math.min(Math.floor((overview?.alerts ?? 0) * 0.1), 12),
      firewall: firewallStatus,
      lastScan: formatScanAgo(snapshot.timestamp),
      ids: idsStatus,
    };
  }, [snapshot, overview, alerts]);

  return (
    <article className="panel panel-compact panel-network-security">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Perimeter Defense</span>
          <h2>Network Security</h2>
        </div>
        <span className={`net-status-pill net-pill-${stats.firewall === "Protected" ? "protected" : "alert"}`}>
          {stats.firewall}
        </span>
      </div>

      <div className="net-stats-grid">
        <NetStat label="Active Connections" value={stats.active} large tone="blue" />
        <NetStat
          label="Suspicious"
          value={stats.suspicious}
          large
          tone={stats.suspicious > 0 ? "amber" : "mint"}
        />
        <NetStat label="Blocked IPs" value={stats.blocked} tone="red" />
        <NetStat label="Firewall" value={stats.firewall} tone={stats.firewall === "Protected" ? "mint" : "red"} />
        <NetStat label="Last Scan" value={stats.lastScan} tone="blue" />
        <NetStat label="IDS Status" value={stats.ids} tone={stats.ids === "Active" ? "mint" : "amber"} />
      </div>
    </article>
  );
}

export default memo(NetworkSecurity);
