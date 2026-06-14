import { useState, useEffect } from "react";
import MarkdownText from "./MarkdownText.jsx";

export default function AIThreatSummary({ geminiAnalysis, mitreMapping, onSpeak }) {
  const [refreshing, setRefreshing] = useState(false);
  const [showMitre, setShowMitre] = useState(false);
  const [geminiStatus, setGeminiStatus] = useState(null);

  async function fetchStatus() {
    try {
      const data = await fetch("/api/gemini/status").then((r) => r.json());
      setGeminiStatus(data);
    } catch {
      /* ignore */
    }
  }

  async function fetchAnalysis() {
    setRefreshing(true);
    try {
      await fetch("/api/gemini/analyze").then((r) => r.json());
      await fetchStatus(); // refresh status after re-analysis
    } catch {
      /* ignore */
    } finally {
      setTimeout(() => setRefreshing(false), 1200);
    }
  }

  // Fetch status on mount and every 30s
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const analysis = geminiAnalysis?.analysis || "";
  const provider = geminiAnalysis?.provider || "unknown";
  const model = geminiAnalysis?.model || "";
  const error = geminiAnalysis?.error;
  const statusDetail = geminiAnalysis?.status || geminiStatus?.status_detail || "";
  const fallbackReason = geminiAnalysis?.fallback_reason || geminiStatus?.init_error || geminiStatus?.last_error || "";
  const techniques = mitreMapping?.techniques || [];
  const tactics = mitreMapping?.active_tactics || [];

  const isGemini = provider === "gemini";

  return (
    <article className="panel panel-gemini">
      <div className="panel-header">
        <div>
          <span className="eyebrow">
            {isGemini ? "Gemini Threat Intelligence" : "AI Threat Intelligence"}
          </span>
          <h2>AI Threat Analysis</h2>
        </div>
        <div className="ai-header-right">
          <button
            className="ai-refresh-btn"
            onClick={fetchAnalysis}
            disabled={refreshing}
            title="Re-analyze with Gemini"
          >
            {refreshing ? "⟳" : "↻"}
          </button>
        </div>
      </div>

      {/* ── Engine Status Indicator ── */}
      <div className={`gemini-engine-status ${isGemini ? "gemini-engine-online" : "gemini-engine-fallback"}`}>
        {isGemini ? (
          <>
            <div className="gemini-engine-row">
              <span className="gemini-engine-dot gemini-dot-online" />
              <span className="gemini-engine-title">Gemini Threat Intelligence Online</span>
            </div>
            <div className="gemini-engine-meta">
              <span>Model: <strong>{model || geminiStatus?.model || "gemini"}</strong></span>
              <span className="gemini-engine-sep">·</span>
              <span>Analysis Status: <strong className="gemini-status-active">Active</strong></span>
            </div>
            {statusDetail && statusDetail.includes("recovered") && (
              <p className="gemini-engine-note">{statusDetail}</p>
            )}
          </>
        ) : (
          <>
            <div className="gemini-engine-row">
              <span className="gemini-engine-dot gemini-dot-fallback" />
              <span className="gemini-engine-title">Local Threat Intelligence Active</span>
            </div>
            <div className="gemini-engine-meta">
              <span>Model: <strong>Trinetra Algorithm</strong></span>
              <span className="gemini-engine-sep">·</span>
              <span>Reason: <strong className="gemini-status-fallback">{fallbackReason || "Gemini service unavailable"}</strong></span>
            </div>
            {statusDetail && (
              <p className="gemini-engine-note">{statusDetail}</p>
            )}
          </>
        )}
      </div>

      {/* ── Error / Notice ── */}
      {error && (
        <p className="gemini-notice">{error}</p>
      )}

      {/* ── Analysis Text ── */}
      <div className="gemini-analysis">
        {analysis ? (
          <MarkdownText text={analysis} />
        ) : (
          <p className="muted">Waiting for threat analysis...</p>
        )}
      </div>

      {/* ── MITRE ATT&CK Toggle ── */}
      {techniques.length > 0 && (
        <>
          <button
            className="mitre-toggle-btn"
            onClick={() => setShowMitre(!showMitre)}
          >
            <span>MITRE ATT&CK Mapping</span>
            <span className="mitre-count">{techniques.length} technique(s)</span>
            <span className="mitre-chevron">{showMitre ? "▲" : "▼"}</span>
          </button>

          {showMitre && (
            <div className="mitre-panel">
              {/* Active Tactics */}
              {tactics.length > 0 && (
                <div className="mitre-tactics">
                  {tactics.map((t) => (
                    <span key={t} className="mitre-tactic-tag">{t}</span>
                  ))}
                </div>
              )}

              {/* Techniques Table */}
              <div className="mitre-table-wrap">
                <table className="mitre-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Technique</th>
                      <th>Tactic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {techniques.map((t) => (
                      <tr key={t.technique_id}>
                        <td className="mono">{t.technique_id}</td>
                        <td>
                          <strong>{t.name}</strong>
                          <br />
                          <small className="dim">{t.description?.slice(0, 90)}...</small>
                        </td>
                        <td>{t.tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── Voice Button ── */}
      {onSpeak && analysis && (
        <div className="gemini-actions">
          <button className="voice-btn" onClick={() => onSpeak(analysis)}>
            🔊 Voice Summary
          </button>
        </div>
      )}
    </article>
  );
}
