import { memo, useMemo } from "react";

function formatUptime(seconds) {
  if (!seconds || seconds < 0) return "--";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function formatTemp(value, cpuLoad) {
  if (value != null && value > 0) return `${Math.round(value)}°C`;
  if (cpuLoad == null) return "--";
  if (cpuLoad >= 90) return "Hot";
  if (cpuLoad >= 70) return "Warm";
  return "Normal";
}

function tempPercent(value, cpuLoad) {
  if (value != null && value > 0) return Math.min((value / 100) * 100, 100);
  if (cpuLoad == null) return 0;
  return Math.min(cpuLoad * 0.85, 100);
}

const HealthMetric = memo(function HealthMetric({ label, value, percent, sub, tone = "mint" }) {
  const safePercent = Math.min(Math.max(percent ?? 0, 0), 100);
  return (
    <div className={`health-metric health-tone-${tone}`}>
      <div className="health-metric-head">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      {sub && <small className="health-metric-sub">{sub}</small>}
      {percent != null && (
        <div className="bar-track health-bar-track">
          <div
            className={`bar-fill health-bar-fill health-bar-${tone}`}
            style={{ width: `${safePercent}%` }}
          />
        </div>
      )}
    </div>
  );
});

function SystemHealth({ snapshot = {} }) {
  const metrics = useMemo(() => {
    const freeGb = Math.max((snapshot.storage_total_gb ?? 0) - (snapshot.storage_used_gb ?? 0), 0);
    const diskHealth = snapshot.disk_health
      || (snapshot.storage_percent >= 95
        ? "Critical"
        : snapshot.storage_percent >= 85
          ? "Warning"
          : "Healthy");

    return {
      cpuTemp: formatTemp(snapshot.cpu_temp, snapshot.cpu),
      cpuTempPct: tempPercent(snapshot.cpu_temp, snapshot.cpu),
      gpuTemp: formatTemp(snapshot.gpu_temp, null),
      gpuTempPct: tempPercent(snapshot.gpu_temp, 0),
      ramPct: snapshot.memory ?? 0,
      swapPct: snapshot.swap_percent ?? 0,
      swapSub: snapshot.swap_total_gb
        ? `${snapshot.swap_used_gb ?? 0} / ${snapshot.swap_total_gb} GB`
        : null,
      storagePct: snapshot.storage_percent ?? 0,
      freeSpace: freeGb ? `${freeGb.toFixed(1)} GB free` : "--",
      diskHealth,
      uptime: formatUptime(snapshot.uptime_seconds),
    };
  }, [snapshot]);

  return (
    <article className="panel panel-compact panel-system-health">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Hardware &amp; System</span>
          <h2>System Health</h2>
        </div>
        <span className={`health-status-pill health-pill-${metrics.diskHealth.toLowerCase()}`}>
          {metrics.diskHealth}
        </span>
      </div>

      <div className="health-section">
        <span className="health-section-label">Hardware</span>
        <div className="health-metrics-grid">
          <HealthMetric
            label="CPU Temperature"
            value={metrics.cpuTemp}
            percent={metrics.cpuTempPct}
            tone={metrics.cpuTempPct >= 80 ? "red" : metrics.cpuTempPct >= 60 ? "amber" : "mint"}
          />
          <HealthMetric
            label="GPU Temperature"
            value={metrics.gpuTemp}
            percent={metrics.gpuTempPct || undefined}
            tone="blue"
          />
        </div>
      </div>

      <div className="health-section">
        <span className="health-section-label">Memory</span>
        <div className="health-metrics-grid">
          <HealthMetric
            label="RAM Usage"
            value={`${snapshot.memory ?? "--"}%`}
            percent={metrics.ramPct}
            sub={snapshot.memory_total_gb ? `${snapshot.memory_used_gb ?? "--"} / ${snapshot.memory_total_gb} GB` : null}
            tone={metrics.ramPct >= 90 ? "red" : metrics.ramPct >= 75 ? "amber" : "mint"}
          />
          <HealthMetric
            label="Swap Usage"
            value={snapshot.swap_percent != null ? `${snapshot.swap_percent}%` : "--"}
            percent={snapshot.swap_percent != null ? metrics.swapPct : undefined}
            sub={metrics.swapSub}
            tone={metrics.swapPct >= 80 ? "amber" : "blue"}
          />
        </div>
      </div>

      <div className="health-section">
        <span className="health-section-label">Storage</span>
        <div className="health-metrics-grid">
          <HealthMetric
            label="Disk Health"
            value={metrics.diskHealth}
            tone={metrics.diskHealth === "Critical" ? "red" : metrics.diskHealth === "Warning" ? "amber" : "mint"}
          />
          <HealthMetric
            label="Free Space"
            value={metrics.freeSpace}
            percent={100 - metrics.storagePct}
            sub={snapshot.storage_percent != null ? `${snapshot.storage_percent}% used` : null}
            tone={metrics.storagePct >= 90 ? "red" : "blue"}
          />
        </div>
      </div>

      <div className="health-section health-section-inline">
        <span className="health-section-label">System</span>
        <div className="health-uptime-block">
          <span>Uptime</span>
          <strong>{metrics.uptime}</strong>
        </div>
      </div>
    </article>
  );
}

export default memo(SystemHealth);
