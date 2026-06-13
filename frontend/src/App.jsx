import Header from "./components/Header.jsx";
import SecurityIndex from "./components/SecurityIndex.jsx";
import EndpointStatus from "./components/EndpointStatus.jsx";
import { AlertsStatCard, AIAttributedStatCard, USBEventsStatCard } from "./components/StatCards.jsx";
import SystemHealth from "./components/SystemHealth.jsx";
import NetworkSecurity from "./components/NetworkSecurity.jsx";
import LiveThreatFeed from "./components/LiveThreatFeed.jsx";
import ThreatSummary from "./components/ThreatSummary.jsx";
import AlertTimeline from "./components/AlertTimeline.jsx";
import LogDetection from "./components/LogDetection.jsx";
import ActiveProcesses from "./components/ActiveProcesses.jsx";
import ModuleMatrix from "./components/ModuleMatrix.jsx";
import AIAnalysis from "./components/AIAnalysis.jsx";
import AIThreatSummary from "./components/AIThreatSummary.jsx";
import ExplainAlertModal from "./components/ExplainAlertModal.jsx";
import VoiceAlertPlayer from "./components/VoiceAlertPlayer.jsx";
import SystemActivity from "./components/SystemActivity.jsx";
import USBSecurity from "./components/USBSecurity.jsx";
import CollectorHealth from "./components/CollectorHealth.jsx";
import Toast from "./components/Toast.jsx";
import { useDashboard } from "./hooks/useDashboard.js";
import { useState, useCallback, useRef } from "react";

export default function App() {
  const { overview, alerts, processes, snapshot, logStream, modules, activity, usbStatus, aiAnalysis, geminiAnalysis, mitreMapping, voiceLanguages, voiceAvailable, toast, resetAlerts } = useDashboard();
  const [explainAlert, setExplainAlert] = useState(null);
  const voicePlayerRef = useRef(null);

  // When user clicks "Voice Summary" in AIThreatSummary,
  // trigger the VoiceAlertPlayer's play with the same analysis text
  const handleSpeakAnalysis = useCallback(() => {
    if (voicePlayerRef.current?.play) voicePlayerRef.current.play();
  }, []);

  return (
    <>
      <Header />
      <main className="dashboard">
        <section className="grid-dashboard">
          <SecurityIndex overview={overview} />
          <EndpointStatus snapshot={snapshot} />
          <AlertsStatCard overview={overview} />
          <AIAttributedStatCard overview={overview} />
          <SystemHealth snapshot={snapshot} />
          <USBEventsStatCard overview={overview} />
          <NetworkSecurity snapshot={snapshot} overview={overview} alerts={alerts} />
        </section>

        <section className="grid-main">
          <LiveThreatFeed alerts={alerts} activity={activity} processes={processes} onReset={resetAlerts} onExplainAlert={setExplainAlert} />
          <aside className="sidebar">
            <USBSecurity usbStatus={usbStatus} />
            <AIAnalysis analysis={aiAnalysis} />
            <ThreatSummary alerts={alerts} analysis={aiAnalysis} />
            <AlertTimeline alerts={alerts} />
          </aside>
        </section>

        <section className="grid-ai-row">
          <AIThreatSummary
            geminiAnalysis={geminiAnalysis}
            mitreMapping={mitreMapping}
            onSpeak={handleSpeakAnalysis}
          />
          <VoiceAlertPlayer
            ref={voicePlayerRef}
            languages={voiceLanguages}
            voiceAvailable={voiceAvailable}
            geminiAnalysis={geminiAnalysis}
          />
        </section>

        <section className="grid-full">
          <ModuleMatrix modules={modules} />
        </section>

        <section className="grid-full">
          <LogDetection logStream={logStream} />
        </section>

        <section className="grid-full">
          <CollectorHealth telemetry={overview?.telemetry} />
        </section>

        <section className="grid-bottom">
          <ActiveProcesses processes={processes} />
          <SystemActivity activity={activity} processes={processes} snapshot={snapshot} />
        </section>

      </main>
      {explainAlert && (
        <ExplainAlertModal
          alert={explainAlert}
          onClose={() => setExplainAlert(null)}
        />
      )}
      <Toast toast={toast} />
    </>
  );
}
