import { useState, useCallback } from "react";

const CATEGORY_LABELS = {
  browser: "Browser",
  messaging: "Messaging",
  media: "Media",
  "cloud-sync": "Cloud Sync",
  updater: "Updater",
  office: "Office",
  "dev-tools": "Dev Tools",
  remote: "Remote",
  misc: "Other",
};

const CATEGORY_COLORS = {
  browser: "var(--blue)",
  messaging: "var(--mint)",
  media: "var(--amber)",
  "cloud-sync": "#9b7dff",
  updater: "var(--text-muted)",
  office: "#5eb4ff",
  "dev-tools": "#ff9a5c",
  remote: "var(--red)",
  misc: "var(--text-muted)",
};

export default function PerformanceOptimizer({ currentScore }) {
  const [scanning, setScanning] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [data, setData] = useState(null);
  const [killing, setKilling] = useState(null); // pid being killed
  const [batchKilling, setBatchKilling] = useState(false);
  const [showProtected, setShowProtected] = useState(false);
  const [messages, setMessages] = useState([]);

  const addMessage = useCallback((text, danger = false) => {
    const id = Date.now() + Math.random();
    setMessages((prev) => [...prev, { id, text, danger }]);
    setTimeout(() => setMessages((prev) => prev.filter((m) => m.id !== id)), 3500);
  }, []);

  async function handleScan() {
    if (!expanded) {
      setExpanded(true);
    }
    setScanning(true);
    try {
      const res = await fetch("/api/optimizer/scan").then((r) => r.json());
      setData(res);
    } catch {
      addMessage("Scan failed — is the backend running?", true);
    } finally {
      setScanning(false);
    }
  }

  async function killProcess(pid, name) {
    setKilling(pid);
    try {
      const res = await fetch("/api/optimizer/kill", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pid, name }),
      }).then((r) => r.json());

      if (res.success) {
        addMessage(`Stopped ${name} (PID ${pid})`);
      } else {
        addMessage(res.error || `Failed to stop ${name}`, true);
      }
      // Re-scan after kill
      setTimeout(handleScan, 800);
    } catch {
      addMessage("Kill request failed", true);
    } finally {
      setKilling(null);
    }
  }

  async function killAllSafe() {
    setBatchKilling(true);
    try {
      const res = await fetch("/api/optimizer/kill-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }).then((r) => r.json());

      addMessage(`Killed ${res.killed} process(es)${res.failed ? `, ${res.failed} failed` : ""}${res.skipped_moderate ? `, ${res.skipped_moderate} skipped (unsaved work risk)` : ""}`);
      setTimeout(handleScan, 1000);
    } catch {
      addMessage("Batch kill failed", true);
    } finally {
      setBatchKilling(false);
    }
  }

  const optimizable = data?.optimizable || [];
  const protected_list = data?.protected || [];
  const summary = data?.summary || {};
  const safeProcesses = optimizable.filter((p) => p.risk === "safe");

  return (
    <div className="optimizer-section">
      {/* ── Toggle Button ── */}
      <button
        className={`optimizer-btn ${expanded ? "optimizer-btn-active" : ""}`}
        onClick={handleScan}
        disabled={scanning}
      >
        <span className="optimizer-btn-icon">⚡</span>
        <span className="optimizer-btn-text">
          {scanning ? "Scanning Processes..." : expanded ? "Refresh Scan" : "Optimize Performance"}
        </span>
        {summary.optimizable_count > 0 && (
          <span className="optimizer-badge">{summary.optimizable_count}</span>
        )}
      </button>

      {/* ── Slide-down Panel ── */}
      {expanded && data && (
        <div className="optimizer-panel">
          {/* Summary bar */}
          <div className="optimizer-summary">
            <div className="optimizer-stat">
              <strong>{summary.optimizable_count || 0}</strong>
              <span>Optimizable</span>
            </div>
            <div className="optimizer-stat optimizer-stat-protected">
              <strong>{summary.protected_count || 0}</strong>
              <span>Protected</span>
            </div>
            <div className="optimizer-stat">
              <strong>{summary.cpu_saved_pct || 0}%</strong>
              <span>CPU Recoverable</span>
            </div>
            <div className="optimizer-stat">
              <strong>{summary.ram_saved_mb || 0} MB</strong>
              <span>RAM Recoverable</span>
            </div>
          </div>

          {/* Stop All Safe button */}
          {safeProcesses.length > 0 && (
            <button
              className="optimizer-stop-all-btn"
              onClick={killAllSafe}
              disabled={batchKilling}
            >
              {batchKilling ? "Stopping..." : `Stop All Safe (${safeProcesses.length})`}
            </button>
          )}

          {/* Process list */}
          {optimizable.length === 0 ? (
            <div className="optimizer-empty">
              <span className="optimizer-empty-icon">✓</span>
              <p>No optimizable processes found. System is running efficiently.</p>
            </div>
          ) : (
            <div className="optimizer-list">
              {optimizable.map((proc) => (
                <div
                  key={`${proc.name}-${proc.pid}`}
                  className={`optimizer-process-row risk-${proc.risk}`}
                >
                  <div className="optimizer-proc-info">
                    <span className="optimizer-proc-name">
                      {proc.name}
                      {proc.instances > 1 && (
                        <span className="optimizer-proc-count"> x{proc.instances}</span>
                      )}
                    </span>
                    <span
                      className="optimizer-category-tag"
                      style={{ color: CATEGORY_COLORS[proc.category] || "var(--text-muted)", borderColor: CATEGORY_COLORS[proc.category] || "var(--border)" }}
                    >
                      {CATEGORY_LABELS[proc.category] || proc.category}
                    </span>
                  </div>

                  <div className="optimizer-proc-stats">
                    <span className="optimizer-metric">{proc.cpu}% CPU</span>
                    <span className="optimizer-metric">{proc.ram_mb} MB</span>
                  </div>

                  {proc.risk === "moderate" && (
                    <span className="optimizer-warning">May have unsaved work</span>
                  )}

                  <button
                    className={`optimizer-stop-btn ${killing === proc.pid ? "optimizer-stopping" : ""}`}
                    onClick={() => killProcess(proc.pid, proc.name)}
                    disabled={killing !== null}
                    title={`Stop ${proc.name}`}
                  >
                    {killing === proc.pid ? "..." : "Stop"}
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Protected processes (collapsed) */}
          {protected_list.length > 0 && (
            <div className="optimizer-protected-section">
              <button
                className="optimizer-protected-toggle"
                onClick={() => setShowProtected(!showProtected)}
              >
                <span>Protected Processes</span>
                <span className="optimizer-protected-count">{protected_list.length} Windows-critical</span>
                <span>{showProtected ? "▲" : "▼"}</span>
              </button>
              {showProtected && (
                <div className="optimizer-protected-list">
                  {protected_list.map((proc) => (
                    <div key={proc.pid} className="optimizer-protected-row">
                      <span className="optimizer-protected-name">{proc.name}</span>
                      <span className="optimizer-protected-cpu">{proc.cpu}% CPU</span>
                      <span className="optimizer-protected-reason">{proc.reason}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Toast messages ── */}
      <div className="optimizer-messages">
        {messages.map((m) => (
          <div key={m.id} className={`optimizer-msg ${m.danger ? "optimizer-msg-danger" : ""}`}>
            {m.text}
          </div>
        ))}
      </div>
    </div>
  );
}
