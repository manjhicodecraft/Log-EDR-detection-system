import { useState } from "react";
import { posture, severityColor } from "../utils/helpers.js";
import MarkdownText from "./MarkdownText.jsx";
import PerformanceOptimizer from "./PerformanceOptimizer.jsx";

const PHASE_CONFIG = {
  immediate: {
    label: "DO NOW",
    icon: "🔴",
    color: "var(--red)",
    bg: "rgba(255, 92, 122, 0.06)",
    border: "rgba(255, 92, 122, 0.2)",
  },
  investigate: {
    label: "INVESTIGATE",
    icon: "🟡",
    color: "var(--amber)",
    bg: "rgba(240, 180, 41, 0.05)",
    border: "rgba(240, 180, 41, 0.2)",
  },
  prevent: {
    label: "PREVENT",
    icon: "🟢",
    color: "var(--mint)",
    bg: "rgba(46, 230, 184, 0.04)",
    border: "rgba(46, 230, 184, 0.2)",
  },
};

export default function SecurityIndex({ overview }) {
  const score = overview?.score ?? 0;
  const severity = overview?.severity ?? "low";
  const color = severityColor(severity);
  const [title, text] = posture(score);
  const ringDeg = Math.min(score, 150) / 150 * 360;
  const remediations = overview?.remediations || [];
  const [expandedIdx, setExpandedIdx] = useState(-1);

  function toggleExpand(idx) {
    setExpandedIdx((prev) => (prev === idx ? -1 : idx));
  }

  const severityDotColor = (sev) => {
    if (sev === "critical" || sev === "high") return "var(--red)";
    if (sev === "medium") return "var(--amber)";
    return "var(--mint)";
  };

  const isEmergency = (item) => item.event_type === "emergency_escalation";

  const totalSteps = (item) =>
    (item.immediate?.length || 0) +
    (item.investigate?.length || 0) +
    (item.prevent?.length || 0) +
    (item.context?.length || 0);

  return (
    <article className="panel panel-hero">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Threat Posture</span>
          <h2>Security Index</h2>
        </div>
        <span className={`badge badge-${severity}`}>{severity.toUpperCase()} RISK</span>
      </div>
      <div className="score-layout">
        <div
          className="score-ring"
          style={{
            background: `conic-gradient(var(--${color}) ${ringDeg}deg, var(--surface-3) 0)`,
          }}
        >
          <div className="score-ring-inner">
            <strong>{score}</strong>
            <small>Risk Score</small>
          </div>
        </div>
        <div className="score-info">
          <h3>{title}</h3>
          <p>{text}</p>
          <div className="risk-bar">
            <span className="risk-seg mint" />
            <span className="risk-seg amber" />
            <span className="risk-seg orange" />
            <span className="risk-seg red" />
          </div>
          <div className="risk-labels">
            <small>Low</small>
            <small>Critical</small>
          </div>
        </div>
      </div>

      {/* ── Performance Optimizer ── */}
      <PerformanceOptimizer currentScore={score} />

      {/* ── Remediation Steps Section ── */}
      {remediations.length > 0 && (
        <div className="remediation-section">
          <div className="remediation-header">
            <div>
              <span className="eyebrow">How to Fix</span>
              <h3>
                {remediations.length} Action{remediations.length > 1 ? "s" : ""} Required
                <span className="remediation-step-count">
                  {remediations.reduce((sum, r) => sum + totalSteps(r), 0)} total steps
                </span>
              </h3>
            </div>
          </div>
          <div className="remediation-list">
            {remediations.map((item, idx) => {
              const emergency = isEmergency(item);
              const expanded = expandedIdx === idx;

              return (
                <div
                  key={item.event_type}
                  className={`remediation-card remediation-priority-${item.priority} ${expanded ? "expanded" : ""} ${emergency ? "remediation-emergency" : ""}`}
                >
                  <button
                    className="remediation-toggle"
                    onClick={() => toggleExpand(idx)}
                  >
                    <span
                      className="remediation-dot"
                      style={{ background: severityDotColor(item.severity) }}
                    />
                    <div className="remediation-title-block">
                      <strong>
                        {emergency && <span className="remediation-emergency-tag">EMERGENCY</span>}
                        {item.threat}
                      </strong>
                      <span className="remediation-meta">
                        {item.event_count > 1 && (
                          <span className="remediation-event-count">{item.event_count} events</span>
                        )}
                        <span>{totalSteps(item)} steps</span>
                      </span>
                    </div>
                    <span className="remediation-chevron">
                      {expanded ? "▾" : "▸"}
                    </span>
                  </button>

                  {expanded && (
                    <div className="remediation-phases">
                      {/* Context steps from event metadata */}
                      {item.context?.length > 0 && (
                        <div className="remediation-phase remediation-phase-context">
                          <div className="remediation-phase-header">
                            <span className="remediation-phase-icon">📋</span>
                            <span>DETECTED CONTEXT</span>
                          </div>
                          <ul className="remediation-steps remediation-steps-context">
                            {item.context.map((step, sIdx) => (
                              <li key={sIdx}><MarkdownText text={step} /></li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* 3-phase steps */}
                      {["immediate", "investigate", "prevent"].map((phase) => {
                        const steps = item[phase];
                        if (!steps || steps.length === 0) return null;
                        const cfg = PHASE_CONFIG[phase];
                        return (
                          <div
                            key={phase}
                            className="remediation-phase"
                            style={{
                              borderLeftColor: cfg.color,
                              background: cfg.bg,
                            }}
                          >
                            <div className="remediation-phase-header" style={{ color: cfg.color }}>
                              <span className="remediation-phase-icon">{cfg.icon}</span>
                              <span>{cfg.label}</span>
                            </div>
                            <ol className="remediation-steps">
                              {steps.map((step, sIdx) => (
                                <li key={sIdx}><MarkdownText text={step} /></li>
                              ))}
                            </ol>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </article>
  );
}
