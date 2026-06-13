import { memo, useCallback, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import MarkdownText from "./MarkdownText.jsx";

const PHASE_CONFIG = {
  immediate: {
    label: "DO NOW",
    icon: "🔴",
    color: "var(--red)",
    bg: "rgba(255, 92, 122, 0.06)",
  },
  investigate: {
    label: "INVESTIGATE",
    icon: "🟡",
    color: "var(--amber)",
    bg: "rgba(240, 180, 41, 0.05)",
  },
  prevent: {
    label: "PREVENT",
    icon: "🟢",
    color: "var(--mint)",
    bg: "rgba(46, 230, 184, 0.04)",
  },
};

function severityDotColor(sev) {
  if (sev === "critical" || sev === "high") return "var(--red)";
  if (sev === "medium") return "var(--amber)";
  return "var(--mint)";
}

function impactFor(item) {
  const sev = item.severity || "low";
  if (item.event_type === "emergency_escalation" || sev === "critical") {
    return "Critical — immediate endpoint isolation and incident response required.";
  }
  if (sev === "high") {
    return "High — active compromise indicators may allow lateral movement or data loss.";
  }
  if (sev === "medium") {
    return "Medium — suspicious behavior detected; investigate before escalation.";
  }
  return "Low — monitor and verify; apply preventive controls.";
}

function totalSteps(item) {
  return (
    (item.immediate?.length || 0) +
    (item.investigate?.length || 0) +
    (item.prevent?.length || 0) +
    (item.context?.length || 0)
  );
}

const RemediationItem = memo(function RemediationItem({
  item,
  expanded,
  status,
  onToggle,
  onResolve,
  onIgnore,
}) {
  const emergency = item.event_type === "emergency_escalation";
  const description = item.context?.[0] || item.threat;
  const recommended = item.immediate || [];

  const glowClass =
    status === "resolved"
      ? "remediation-glow-resolved"
      : emergency
        ? "remediation-glow-emergency"
        : item.severity === "medium"
          ? "remediation-glow-warning"
          : "remediation-glow-hover";

  return (
    <div
      className={`remediation-card remediation-priority-${item.priority} ${expanded ? "expanded" : ""} ${emergency ? "remediation-emergency" : ""} ${glowClass} remediation-status-${status}`}
    >
      <button
        type="button"
        className="remediation-toggle"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <span
          className="remediation-dot"
          style={{ background: severityDotColor(item.severity) }}
        />
        <div className="remediation-title-block">
          <strong>
            {emergency && <span className="remediation-emergency-tag">EMERGENCY</span>}
            {status === "resolved" && <span className="remediation-resolved-tag">RESOLVED</span>}
            {status === "ignored" && <span className="remediation-ignored-tag">IGNORED</span>}
            {item.threat}
          </strong>
          <span className="remediation-meta">
            {item.event_count > 1 && (
              <span className="remediation-event-count">{item.event_count} events</span>
            )}
            <span>{totalSteps(item)} steps</span>
          </span>
        </div>
        <span className="remediation-chevron" aria-hidden="true">
          {expanded ? "▾" : "▸"}
        </span>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="content"
            className="remediation-expand-wrap"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.35, ease: "easeInOut" }}
          >
            <div className="remediation-expanded-content">
              <div className="remediation-info-block">
                <span className="remediation-info-label">Threat Description</span>
                <p><MarkdownText text={description} /></p>
              </div>

              <div className="remediation-info-block">
                <span className="remediation-info-label">Impact</span>
                <p>{impactFor(item)}</p>
              </div>

              {recommended.length > 0 && (
                <div className="remediation-info-block">
                  <span className="remediation-info-label">Recommended Actions</span>
                  <ul className="remediation-actions-list">
                    {recommended.map((step, sIdx) => (
                      <li key={sIdx}><MarkdownText text={step} /></li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="remediation-phases">
                {item.context?.length > 1 && (
                  <div className="remediation-phase remediation-phase-context">
                    <div className="remediation-phase-header">
                      <span className="remediation-phase-icon">📋</span>
                      <span>DETECTED CONTEXT</span>
                    </div>
                    <ul className="remediation-steps remediation-steps-context">
                      {item.context.slice(1).map((step, sIdx) => (
                        <li key={sIdx}><MarkdownText text={step} /></li>
                      ))}
                    </ul>
                  </div>
                )}

                {["immediate", "investigate", "prevent"].map((phase) => {
                  const steps = item[phase];
                  if (!steps || steps.length === 0) return null;
                  const cfg = PHASE_CONFIG[phase];

                  return (
                    <div
                      key={phase}
                      className="remediation-phase"
                      style={{ borderLeftColor: cfg.color, background: cfg.bg }}
                    >
                      <div className="remediation-phase-header" style={{ color: cfg.color }}>
                        <span className="remediation-phase-icon">{cfg.icon}</span>
                        <span>{cfg.label} — Fix Steps</span>
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

              {status === "open" && (
                <div className="remediation-actions">
                  <button type="button" className="remediation-btn remediation-btn-resolve" onClick={onResolve}>
                    Resolve
                  </button>
                  <button type="button" className="remediation-btn remediation-btn-ignore" onClick={onIgnore}>
                    Ignore
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
});

function RemediationAccordion({ remediations = [] }) {
  const [expandedIdx, setExpandedIdx] = useState(-1);
  const [statusMap, setStatusMap] = useState({});

  const toggleExpand = useCallback((idx) => {
    setExpandedIdx((prev) => (prev === idx ? -1 : idx));
  }, []);

  const setStatus = useCallback((eventType, status) => {
    setStatusMap((prev) => ({ ...prev, [eventType]: status }));
    setExpandedIdx(-1);
  }, []);

  if (remediations.length === 0) return null;

  const stepTotal = remediations.reduce((sum, r) => sum + totalSteps(r), 0);

  return (
    <div className="remediation-section">
      <div className="remediation-header">
        <div>
          <span className="eyebrow">How to Fix</span>
          <h3>
            {remediations.length} Action{remediations.length > 1 ? "s" : ""} Required
            <span className="remediation-step-count">{stepTotal} total steps</span>
          </h3>
        </div>
      </div>

      <div className="remediation-list">
        {remediations.map((item, idx) => (
          <RemediationItem
            key={item.event_type}
            item={item}
            expanded={expandedIdx === idx}
            status={statusMap[item.event_type] || "open"}
            onToggle={() => toggleExpand(idx)}
            onResolve={() => setStatus(item.event_type, "resolved")}
            onIgnore={() => setStatus(item.event_type, "ignored")}
          />
        ))}
      </div>
    </div>
  );
}

export default memo(RemediationAccordion);
