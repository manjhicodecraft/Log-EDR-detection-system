import { memo } from "react";

const StatPreview = memo(function StatPreview({ items = [], empty }) {
  const rows = items.slice(0, 3);
  return (
    <div className="stat-preview-list">
      {rows.length === 0 ? (
        <span className="stat-preview-empty">{empty}</span>
      ) : (
        rows.map((item, index) => (
          <div className={`stat-preview-item severity-${item.severity || "low"}`} key={`${item.title}-${index}`}>
            <span className="stat-preview-dot" />
            <div>
              <strong>{item.title}</strong>
              <small>{item.detail}</small>
            </div>
          </div>
        ))
      )}
    </div>
  );
});

export const AlertsStatCard = memo(function AlertsStatCard({ overview }) {
  const previews = overview?.previews || {};
  return (
    <article className="panel panel-stat grid-cell-alerts">
      <span className="eyebrow">Total Alerts</span>
      <strong className="stat-value">{overview?.alerts ?? 0}</strong>
      <p className="muted">Recorded locally</p>
      <StatPreview items={previews.alerts} empty="No alerts recorded yet" />
    </article>
  );
});

export const AIAttributedStatCard = memo(function AIAttributedStatCard({ overview }) {
  const previews = overview?.previews || {};
  return (
    <article className="panel panel-stat grid-cell-ai">
      <span className="eyebrow">AI Attributed</span>
      <strong className="stat-value">{overview?.ai_attributed ?? 0}</strong>
      <p className="muted">Commands and chains</p>
      <StatPreview items={previews.ai_attributed} empty="No AI-attributed chains" />
    </article>
  );
});

export const USBEventsStatCard = memo(function USBEventsStatCard({ overview }) {
  const previews = overview?.previews || {};
  return (
    <article className="panel panel-stat panel-online grid-cell-usb">
      <span className="eyebrow">USB Events</span>
      <strong className="stat-online">
        <span className="pulse-dot" /> {overview?.usb_events ?? 0}
      </strong>
      <p className="muted">Detected and scanned</p>
      <StatPreview items={previews.usb_events} empty="No USB activity" />
    </article>
  );
});

export default function StatCards({ overview }) {
  return (
    <div className="stat-card-group">
      <AlertsStatCard overview={overview} />
      <AIAttributedStatCard overview={overview} />
      <USBEventsStatCard overview={overview} />
    </div>
  );
}
