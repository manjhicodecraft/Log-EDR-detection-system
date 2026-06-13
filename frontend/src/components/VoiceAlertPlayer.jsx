import { useState, useRef, useEffect, forwardRef, useImperativeHandle } from "react";

const VoiceAlertPlayer = forwardRef(function VoiceAlertPlayer({ languages, voiceAvailable, geminiAnalysis }, ref) {
  const [selectedLang, setSelectedLang] = useState("en");
  const [playing, setPlaying] = useState(false);
  const [status, setStatus] = useState("");
  const [spokenText, setSpokenText] = useState("");
  const audioRef = useRef(null);

  // Expose play() to parent so AIThreatSummary "Voice Summary" button can trigger it
  useImperativeHandle(ref, () => ({
    play: () => speakText(),
  }));

  const useBrowserTTS = !voiceAvailable;

  // ── Extract live analysis text from Gemini output ──
  function getAnalysisText() {
    const analysis = geminiAnalysis?.analysis || "";
    if (analysis) return analysis;
    // Fallback when no Gemini data yet
    if (selectedLang === "hi")
      return "Trinetra Sentinel security alert. System mein suraksha ghatnaayein detect hui hain. Kripya dashboard ki samiksha karein aur uchch priority alerts par dhyaan dein.";
    if (selectedLang === "te")
      return "Trinetra Sentinel security alert. System lo bhadratha gathanalu gurthinchabaadayaayi. Dayachesi dashboard ni parishilinchandi mariyu high priority alerts ni gurthinchandi.";
    return "Trinetra Sentinel security alert. Security events have been detected on this system. Please review the dashboard and prioritize high severity alerts.";
  }

  const hasLiveAnalysis = !!geminiAnalysis?.analysis;

  async function speakText() {
    if (playing) {
      stopAudio();
      return;
    }

    setStatus("Generating voice...");
    setPlaying(true);

    const analysisText = getAnalysisText();

    if (useBrowserTTS) {
      // ── Browser-native TTS fallback ──
      const utterance = new SpeechSynthesisUtterance(analysisText);
      utterance.lang = selectedLang === "hi" ? "hi-IN" : selectedLang === "te" ? "te-IN" : "en-IN";
      utterance.rate = 0.9;
      utterance.onend = () => { setPlaying(false); setStatus(""); };
      utterance.onerror = () => { setPlaying(false); setStatus("Speech synthesis failed"); };
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(utterance);
      setSpokenText(analysisText);
      return;
    }

    // ── Sarvam AI TTS via /api/voice/analysis ──
    // This endpoint creates a short summary from Gemini output + synthesizes voice
    try {
      const data = await fetch("/api/voice/analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: analysisText, language: selectedLang }),
      }).then((r) => r.json());

      setSpokenText(data.text || analysisText);

      if (data.audio_base64 && data.format !== "browser-fallback") {
        const audio = new Audio(`data:audio/wav;base64,${data.audio_base64}`);
        audioRef.current = audio;
        audio.onended = () => { setPlaying(false); setStatus(""); };
        audio.onerror = () => { setPlaying(false); setStatus("Audio playback failed"); };
        audio.play();
        setStatus(`Playing via ${data.provider}`);
      } else {
        // Fallback to browser TTS with the summarized text
        const utterance = new SpeechSynthesisUtterance(data.text || analysisText);
        utterance.lang = selectedLang === "hi" ? "hi-IN" : selectedLang === "te" ? "te-IN" : "en-IN";
        utterance.rate = 0.9;
        utterance.onend = () => { setPlaying(false); setStatus(""); };
        window.speechSynthesis.cancel();
        window.speechSynthesis.speak(utterance);
        setStatus("Browser speech (fallback)");
      }
    } catch {
      // Final fallback — browser TTS with raw analysis
      const utterance = new SpeechSynthesisUtterance(analysisText);
      utterance.lang = selectedLang === "hi" ? "hi-IN" : selectedLang === "te" ? "te-IN" : "en-IN";
      utterance.rate = 0.9;
      utterance.onend = () => { setPlaying(false); setStatus(""); };
      window.speechSynthesis.speak(utterance);
      setSpokenText(analysisText);
      setStatus("Browser speech (offline)");
    }
  }

  function stopAudio() {
    window.speechSynthesis?.cancel();
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current = null;
    }
    setPlaying(false);
    setStatus("");
  }

  useEffect(() => {
    return () => {
      window.speechSynthesis?.cancel();
      if (audioRef.current) audioRef.current.pause();
    };
  }, []);

  const langList = languages || [
    { code: "en", label: "English", native: "English" },
    { code: "hi", label: "Hindi", native: "हिन्दी" },
    { code: "te", label: "Telugu", native: "తెలుగు" },
  ];

  return (
    <article className="panel panel-voice">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Sarvam AI Voice Assistant</span>
          <h2>Voice Alerts</h2>
        </div>
        <span className={`ai-chip ${useBrowserTTS ? "voice-chip-fallback" : ""}`}>
          {useBrowserTTS ? "Browser TTS" : "Sarvam AI"}
        </span>
      </div>

      <p className="voice-desc">
        Hear Gemini's threat analysis as a short voice summary in English, Hindi, or Telugu.
        {hasLiveAnalysis
          ? " ✅ Live Gemini analysis ready."
          : " ⏳ Waiting for Gemini analysis..."}
      </p>

      {/* Language selector */}
      <div className="voice-lang-select">
        {langList.map((lang) => (
          <button
            key={lang.code}
            className={`voice-lang-btn ${selectedLang === lang.code ? "voice-lang-active" : ""}`}
            onClick={() => setSelectedLang(lang.code)}
          >
            <span className="voice-lang-native">{lang.native}</span>
            <span className="voice-lang-label">{lang.label}</span>
          </button>
        ))}
      </div>

      {/* Play / Stop button */}
      <div className="voice-controls">
        <button
          className={`voice-play-btn ${playing ? "voice-playing" : ""}`}
          onClick={speakText}
        >
          {playing ? "⏹ Stop" : "🔊 Play Voice Summary"}
        </button>
        {status && <span className="voice-status">{status}</span>}
      </div>

      {/* Show what will be / was spoken */}
      {spokenText && (
        <div className="voice-spoken-text">
          <span className="eyebrow">Spoken text:</span>
          <p>{spokenText.slice(0, 220)}{spokenText.length > 220 ? "…" : ""}</p>
        </div>
      )}

      <div className="voice-footer">
        <span>Source: Gemini Analysis</span>
        <strong>3 Languages</strong>
        <span>Read-only</span>
      </div>
    </article>
  );
});

export default VoiceAlertPlayer;
