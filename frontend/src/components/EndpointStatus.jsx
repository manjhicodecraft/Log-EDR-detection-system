export default function EndpointStatus({ snapshot }) {
  return (
    <article className="panel grid-cell-endpoint">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Endpoint Status</span>
          <h2>{snapshot.hostname || "Local workstation"}</h2>
        </div>
        <span className="shield-icon" aria-label="Protected">✓</span>
      </div>
      <p className="muted">{snapshot.os || "Detecting host operating system..."}</p>
      <div className="metrics-grid">
        <Metric label="CPU Load" value={`${snapshot.cpu ?? "--"}%`} percent={snapshot.cpu} />
        <Metric
          label="Memory"
          value={`${snapshot.memory ?? "--"}%`}
          percent={snapshot.memory}
          sub={`${snapshot.memory_used_gb ?? "--"} / ${snapshot.memory_total_gb ?? "--"} GB`}
        />
        <div className="metric">
          <span>Processes</span>
          <strong>{snapshot.processes ?? "--"}</strong>
        </div>
        <div className="metric">
          <span>Connections</span>
          <strong>{snapshot.connections ?? "--"}</strong>
        </div>
        <div className="metric">
          <span>Disk R/W</span>
          <strong>{snapshot.disk_read_mb_s ?? "--"} / {snapshot.disk_write_mb_s ?? "--"} MB/s</strong>
        </div>
        <div className="metric">
          <span>Net Up/Down</span>
          <strong>{snapshot.upload_kb_s ?? "--"} / {snapshot.download_kb_s ?? "--"} KB/s</strong>
        </div>
        <div className="metric">
          <span>Storage</span>
          <strong>{snapshot.storage_percent ?? "--"}%</strong>
          <small className="metric-sub">{snapshot.storage_used_gb ?? "--"} / {snapshot.storage_total_gb ?? "--"} GB</small>
        </div>
      </div>
    </article>
  );
}

function Metric({ label, value, percent, sub }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {sub && <small className="metric-sub">{sub}</small>}
      <div className="bar-track">
        <div className="bar-fill" style={{ width: `${percent || 0}%` }} />
      </div>
    </div>
  );
}
