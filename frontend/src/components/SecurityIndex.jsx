import { posture, severityColor } from "../utils/helpers.js";
import PerformanceOptimizer from "./PerformanceOptimizer.jsx";
import RemediationAccordion from "./RemediationAccordion.jsx";

export default function SecurityIndex({ overview }) {
  const score = overview?.score ?? 0;
  const severity = overview?.severity ?? "low";
  const color = severityColor(severity);
  const [title, text] = posture(score);
  const ringDeg = Math.min(score, 150) / 150 * 360;
  const remediations = overview?.remediations || [];

  return (
    <article className="panel panel-hero grid-cell-threat">
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

      <PerformanceOptimizer currentScore={score} />

      <RemediationAccordion remediations={remediations} />
    </article>
  );
}
