import { useState } from "react";
import MarkdownText from "./MarkdownText.jsx";

export default function AIAnalysis({ analysis }) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  async function askQuestion(event) {
    event.preventDefault();
    const text = question.trim();
    if (!text || loading) return;
    setLoading(true);
    setAnswer(null);
    try {
      const data = await fetch("/api/ai-question", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text }),
      }).then((r) => r.json());
      setAnswer(data);
    } catch {
      setAnswer({ answer: "AI request fail ho gaya. Backend running hai ya nahi check karo.", mode: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function forceRefresh() {
    setRefreshing(true);
    try {
      // The parent hook will pick up the new data; this just triggers a force fetch
      await fetch("/api/ai-analysis?force=true").then((r) => r.json());
      // Dispatch a custom event so useDashboard knows to re-fetch
      window.dispatchEvent(new CustomEvent("ai-analysis-refreshed"));
    } catch {
      /* ignore */
    } finally {
      setTimeout(() => setRefreshing(false), 800);
    }
  }

  const evalCount = analysis?.eval_count ?? 0;
  const lastEval = analysis?.last_eval;
  const scoreAtEval = analysis?.score_at_eval;
  const overallRisk = analysis?.overall_risk || "Safe";

  const riskColor =
    overallRisk === "Critical" ? "var(--red)" :
    overallRisk === "High Risk" ? "var(--orange)" :
    overallRisk === "Warning" ? "var(--amber)" :
    "var(--mint)";

  const formatTimeSince = (iso) => {
    if (!iso) return "N/A";
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 30) return "just now";
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  };

  return (
    <article className="panel panel-ai">
      <div className="panel-header">
        <div>
          <span className="eyebrow">AI Analysis Module</span>
          <h2>Live Analysis Report</h2>
        </div>
        <div className="ai-header-right">
          <span className="ai-chip">{analysis?.mode === "local_analysis" ? "Active" : (analysis?.mode || "Analyzing")}</span>
          <button
            className="ai-refresh-btn"
            onClick={forceRefresh}
            disabled={refreshing}
            title="Force re-evaluate analysis"
          >
            {refreshing ? "⟳" : "↻"}
          </button>
        </div>
      </div>

      {/* ── Live Evaluation Status ── */}
      <div className="ai-eval-status">
        <div className="ai-eval-item">
          <span className="ai-eval-label">Evaluations</span>
          <strong className="ai-eval-value">{evalCount}</strong>
        </div>
        <div className="ai-eval-item">
          <span className="ai-eval-label">Last Evaluated</span>
          <strong className="ai-eval-value">{formatTimeSince(lastEval)}</strong>
        </div>
        <div className="ai-eval-item">
          <span className="ai-eval-label">Score at Eval</span>
          <strong className="ai-eval-value" style={{ color: riskColor }}>
            {scoreAtEval ?? "—"}
          </strong>
        </div>
        <div className="ai-eval-item ai-eval-auto">
          <span className="ai-eval-label">Auto-refresh</span>
          <span className="ai-eval-dot" />
          <strong className="ai-eval-value">Active</strong>
        </div>
      </div>

      <div className="ai-risk-line">
        <span>Overall Risk</span>
        <strong style={{ color: riskColor }}>{overallRisk}</strong>
      </div>
      <div className="ai-text">
        {(analysis?.summary || ["Waiting for live telemetry."]).map((line, idx) => (
          <div key={`${idx}-${line.slice(0, 40)}`} className="ai-text-line">
            <MarkdownText text={line} />
          </div>
        ))}
      </div>
      <div className="recommendation-list">
        {(analysis?.recommendations || []).map((item, idx) => (
          <span key={`${idx}-${item.slice(0, 30)}`}>
            <MarkdownText text={item} />
          </span>
        ))}
      </div>
      {analysis?.error && analysis.error !== null ? (
        <div className="ai-error-box">
          <pre className="ai-error-pre">{analysis.error}</pre>
        </div>
      ) : null}
      <form className="ai-question-form" onSubmit={askQuestion}>
        <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask about current process, risk, or overload..."
        />
        <button type="submit" disabled={loading || !question.trim()}>
          {loading ? "Analyzing" : "Ask"}
        </button>
      </form>
      {answer ? (
        <div className="ai-answer">
          <span>{answer.mode || answer.provider || "AI"}</span>
          <MarkdownText text={answer.answer} />
        </div>
      ) : null}
      <div className="ai-footer">
        <span>No commands</span>
        <strong>No file changes</strong>
        <span>No system control</span>
      </div>
    </article>
  );
}
