import { useState, useRef, useEffect, forwardRef, useImperativeHandle, useCallback } from "react";

/* ── Speech Recognition setup (Web Speech API) ── */
const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

const LANG_LOCALES = {
  en: "en-IN",
  hi: "hi-IN",
  mr: "mr-IN",
  gu: "gu-IN",
  te: "te-IN",
};

const VoiceAlertPlayer = forwardRef(function VoiceAlertPlayer({ languages, voiceAvailable, geminiAnalysis, overview, alerts }, ref) {
  const [selectedLang, setSelectedLang] = useState("en");
  const [playing, setPlaying] = useState(false);
  const [status, setStatus] = useState("");
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [listening, setListening] = useState(false);

  // Mode: "chat" | "investigate" | "guided" | "verify"
  const [mode, setMode] = useState("chat");

  // Guided remediation state
  const [guidedState, setGuidedState] = useState({
    currentStep: 0,
    totalSteps: 0,
    completedSteps: [],
    scoreAtStart: 0,
    active: false,
  });

  const audioRef = useRef(null);
  const chatEndRef = useRef(null);
  const inputRef = useRef(null);
  const recognitionRef = useRef(null);

  const useBrowserTTS = !voiceAvailable;

  // Expose play() to parent
  useImperativeHandle(ref, () => ({
    play: () => summarizeThreats(),
  }));

  // Auto-scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // ── Speech Recognition ──
  const startListening = useCallback(() => {
    if (!SpeechRecognition) {
      setStatus("Speech recognition not supported in this browser");
      return;
    }
    const recognition = new SpeechRecognition();
    recognition.lang = LANG_LOCALES[selectedLang] || "en-IN";
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;
    recognition.continuous = false;

    recognition.onstart = () => {
      setListening(true);
      setStatus("Listening...");
    };
    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      setQuestion(transcript);
      setListening(false);
      setStatus("");
      // Auto-send after short delay
      setTimeout(() => {
        const fakeEvent = { preventDefault: () => {} };
        // We set question then trigger send
        sendQuestion(transcript);
      }, 300);
    };
    recognition.onerror = (event) => {
      setListening(false);
      setStatus(event.error === "no-speech" ? "No speech detected" : `Mic error: ${event.error}`);
    };
    recognition.onend = () => setListening(false);

    recognitionRef.current = recognition;
    recognition.start();
  }, [selectedLang]);

  const stopListening = useCallback(() => {
    recognitionRef.current?.stop();
    setListening(false);
    setStatus("");
  }, []);

  // ── Audio playback ──
  const playAudio = useCallback((text, audioBase64, format, provider) => {
    stopAudio();
    setPlaying(true);
    if (audioBase64 && format !== "browser-fallback") {
      const audio = new Audio(`data:audio/wav;base64,${audioBase64}`);
      audioRef.current = audio;
      audio.onended = () => { setPlaying(false); setStatus(""); };
      audio.onerror = () => { setPlaying(false); setStatus("Audio playback failed"); };
      audio.play().catch(() => { setPlaying(false); setStatus("Audio autoplay blocked"); });
      setStatus(`Playing via ${provider}`);
    } else {
      const langCode = LANG_LOCALES[selectedLang] || "en-IN";
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = langCode;
      utterance.rate = 0.9;
      utterance.pitch = 1.0;
      utterance.onend = () => { setPlaying(false); setStatus(""); };
      utterance.onerror = () => { setPlaying(false); setStatus("Speech synthesis failed"); };
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(utterance);
      setStatus("Browser speech");
    }
  }, [selectedLang]);

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
      recognitionRef.current?.stop();
    };
  }, []);

  // ── Helper: add assistant message + play audio ──
  function handleResponse(data, msgMode) {
    const responseText = data.response || "I couldn't process that.";
    const msg = {
      role: "assistant",
      text: responseText,
      audio_base64: data.audio_base64,
      format: data.format,
      provider: data.provider,
      ai_provider: data.ai_provider,
      mode: msgMode || data.mode || "chat",
      current_step: data.current_step,
      total_steps: data.total_steps,
      step_instruction: data.step_instruction,
      is_complete: data.is_complete,
      is_resolved: data.is_resolved,
      remaining_alerts: data.remaining_alerts,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, msg]);
    playAudio(responseText, data.audio_base64, data.format, data.provider);
    return msg;
  }

  // ── Build history for API calls ──
  function getHistory() {
    return messages.slice(-8).map((m) => ({ role: m.role, text: m.text }));
  }

  // ── Send question (chat mode or guided mode) ──
  async function sendQuestion(text) {
    const input = (text || question).trim();
    if (!input || loading) return;

    const userMsg = { role: "user", text: input, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    setQuestion("");
    setLoading(true);
    setStatus("Thinking...");

    try {
      let endpoint, body;

      if (mode === "guided" && guidedState.active) {
        // Send to guided remediation endpoint
        endpoint = "/api/voice/guide";
        body = {
          input: input,
          language: selectedLang,
          current_step: guidedState.currentStep,
          completed_steps: guidedState.completedSteps,
          history: getHistory(),
        };
      } else if (mode === "investigate") {
        endpoint = "/api/voice/investigate";
        body = {
          question: input,
          language: selectedLang,
          history: getHistory(),
        };
      } else {
        endpoint = "/api/voice/converse";
        body = {
          question: input,
          language: selectedLang,
          history: getHistory(),
        };
      }

      const data = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then((r) => r.json());

      const msg = handleResponse(data, mode);

      // Update guided state if in guided mode
      if (mode === "guided" && data.current_step !== undefined) {
        setGuidedState((prev) => ({
          ...prev,
          currentStep: data.current_step,
          totalSteps: data.total_steps || prev.totalSteps,
          completedSteps: data.completed_steps || prev.completedSteps,
        }));
      }

      // If guided step was advanced and is now complete, suggest verification
      if (data.is_complete && mode === "guided") {
        // Auto-transition hint is in the response text
      }
    } catch {
      setMessages((prev) => [...prev, {
        role: "assistant",
        text: "I'm having trouble connecting. Please check if the backend is running.",
        timestamp: new Date().toISOString(),
      }]);
      setStatus("Connection failed");
    } finally {
      setLoading(false);
    }
  }

  // Form submit handler
  async function askQuestion(e) {
    if (e) e.preventDefault();
    sendQuestion();
  }

  // ── Mode switching ──
  function switchMode(newMode) {
    if (newMode === mode) return;
    setMode(newMode);
    if (newMode === "guided" && !guidedState.active) {
      // Start guided mode
      const scoreAtStart = overview?.score ?? 0;
      setGuidedState({ currentStep: 0, totalSteps: 0, completedSteps: [], scoreAtStart, active: true });
      // Auto-send "start" to get first step
      setTimeout(() => sendGuidedStart(), 100);
    }
  }

  async function sendGuidedStart() {
    if (loading) return;
    const userMsg = {
      role: "user",
      text: selectedLang === "hi" ? "Mujhe fix karne mein madad karo." : "Help me fix this.",
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setLoading(true);
    setStatus("Preparing remediation plan...");

    try {
      const data = await fetch("/api/voice/guide", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input: "start guided remediation",
          language: selectedLang,
          current_step: 0,
          completed_steps: [],
          history: getHistory(),
        }),
      }).then((r) => r.json());

      handleResponse(data, "guided");
      if (data.current_step !== undefined) {
        setGuidedState((prev) => ({
          ...prev,
          currentStep: data.current_step,
          totalSteps: data.total_steps || prev.totalSteps,
          completedSteps: data.completed_steps || [],
        }));
      }
    } catch {
      setMessages((prev) => [...prev, {
        role: "assistant", text: "Unable to start guided remediation.", timestamp: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  }

  // ── Investigation mode ──
  async function startInvestigation() {
    switchMode("investigate");
    if (loading) return;
    setLoading(true);
    setStatus("Investigating...");

    const userMsg = {
      role: "user",
      text: selectedLang === "hi" ? "Is khatre ki jaanch karo." : "Investigate this threat.",
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const data = await fetch("/api/voice/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: "Investigate all current threats and provide a detailed analysis.",
          language: selectedLang,
          history: getHistory(),
        }),
      }).then((r) => r.json());

      handleResponse(data, "investigation");
    } catch {
      setMessages((prev) => [...prev, {
        role: "assistant", text: "Investigation failed. Please try again.", timestamp: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  }

  // ── Verification ──
  async function startVerification() {
    if (loading) return;
    setLoading(true);
    setStatus("Verifying resolution...");

    const userMsg = {
      role: "user",
      text: selectedLang === "hi" ? "Verify karo ki khatra tal gaya hai." : "Verify the threat is resolved.",
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const data = await fetch("/api/voice/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: selectedLang,
          previous_score: guidedState.scoreAtStart || overview?.score || 0,
          history: getHistory(),
        }),
      }).then((r) => r.json());

      handleResponse(data, "verification");
    } catch {
      setMessages((prev) => [...prev, {
        role: "assistant", text: "Verification failed. Please try again.", timestamp: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  }

  // ── Summarize threats ──
  async function summarizeThreats() {
    if (loading) return;
    setLoading(true);
    setStatus("Analyzing threats...");
    setMode("chat");

    const score = overview?.score ?? 0;
    const alertCount = alerts?.length ?? 0;
    const summaryQuestion = `Give me a quick summary of the current security status. Risk score is ${score} with ${alertCount} alerts.`;

    const userMsg = {
      role: "user",
      text: selectedLang === "hi" ? "System ka suraksha status batao." : "Summarize current security status.",
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const data = await fetch("/api/voice/converse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: summaryQuestion, language: selectedLang, history: [] }),
      }).then((r) => r.json());
      handleResponse(data, "chat");
    } catch {
      setMessages((prev) => [...prev, {
        role: "assistant", text: "Unable to generate summary.", timestamp: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  }

  function replayMessage(msg) {
    if (playing) { stopAudio(); return; }
    playAudio(msg.text, msg.audio_base64, msg.format, msg.provider);
  }

  const langList = languages || [
    { code: "en", label: "English", native: "English" },
    { code: "hi", label: "Hindi", native: "हिन्दी" },
    { code: "mr", label: "Marathi", native: "मराठी" },
    { code: "gu", label: "Gujarati", native: "ગુજરાતી" },
    { code: "te", label: "Telugu", native: "తెలుగు" },
  ];

  const suggestions = selectedLang === "en"
    ? ["What's the risk level?", "Any threats detected?", "Investigate threats", "Help me fix this"]
    : selectedLang === "hi"
    ? ["Risk level kya hai?", "Koi khatra hai?", "Khatre ki jaanch karo", "Fix karne mein madad karo"]
    : ["What's the risk?", "Any threats?", "Investigate", "Help me fix"];

  const hasThreats = (overview?.score ?? 0) >= 30 || (overview?.critical ?? 0) > 0;

  return (
    <article className="panel panel-voice">
      <div className="panel-header">
        <div>
          <span className="eyebrow">AI Security Analyst</span>
          <h2>Trinetra Voice</h2>
        </div>
        <div className="voice-header-badges">
          {mode !== "chat" && (
            <span className={`voice-mode-badge voice-mode-${mode}`}>
              {mode === "investigate" ? "Investigating" : mode === "guided" ? "Remediation" : "Verifying"}
            </span>
          )}
          <span className={`ai-chip ${useBrowserTTS ? "voice-chip-fallback" : ""}`}>
            {useBrowserTTS ? "Browser TTS" : "Sarvam AI"}
          </span>
        </div>
      </div>

      {/* Language selector */}
      <div className="voice-lang-select">
        {langList.map((lang) => (
          <button key={lang.code}
            className={`voice-lang-btn ${selectedLang === lang.code ? "voice-lang-active" : ""}`}
            onClick={() => setSelectedLang(lang.code)}>
            <span className="voice-lang-native">{lang.native}</span>
            <span className="voice-lang-label">{lang.label}</span>
          </button>
        ))}
      </div>

      {/* Mode tabs */}
      <div className="voice-mode-tabs">
        <button className={`voice-mode-tab ${mode === "chat" ? "active" : ""}`} onClick={() => switchMode("chat")}>Chat</button>
        <button className={`voice-mode-tab ${mode === "investigate" ? "active" : ""}`} onClick={startInvestigation}>Investigate</button>
        {hasThreats && (
          <button className={`voice-mode-tab ${mode === "guided" ? "active" : ""}`} onClick={() => switchMode("guided")}>Fix It</button>
        )}
        {(guidedState.active || mode === "guided") && (
          <button className="voice-mode-tab voice-verify-tab" onClick={startVerification}>Verify</button>
        )}
      </div>

      {/* Guided step progress bar */}
      {mode === "guided" && guidedState.active && guidedState.totalSteps > 0 && (
        <div className="voice-step-progress">
          <div className="voice-step-bar">
            <div className="voice-step-fill" style={{ width: `${(guidedState.currentStep / guidedState.totalSteps) * 100}%` }} />
          </div>
          <span className="voice-step-label">
            Step {Math.min(guidedState.currentStep + 1, guidedState.totalSteps)} / {guidedState.totalSteps}
          </span>
        </div>
      )}

      {/* Chat messages */}
      <div className="voice-chat-area">
        {messages.length === 0 ? (
          <div className="voice-welcome">
            <div className="voice-welcome-icon">🎙️</div>
            <p className="voice-welcome-title">
              {selectedLang === "hi" ? "Trinetra Security Analyst" : "Trinetra Security Analyst"}
            </p>
            <p className="voice-welcome-desc">
              {selectedLang === "hi"
                ? "Main aapka AI security analyst hoon. Khatre ki jaanch, explanation, investigation aur remediation mein madad kar sakta hoon. Mic button dabake bol sakte ho ya type kar sakte ho."
                : "I'm your AI security analyst. I can explain threats, investigate incidents, guide you through remediation step-by-step, and verify when issues are resolved. Speak or type your question."}
            </p>
            <div className="voice-suggestions">
              {suggestions.map((s) => (
                <button key={s} className="voice-suggestion-chip"
                  onClick={() => {
                    if (s.toLowerCase().includes("investigate")) { startInvestigation(); return; }
                    if (s.toLowerCase().includes("fix")) { switchMode("guided"); return; }
                    setQuestion(s);
                    setTimeout(() => inputRef.current?.focus(), 50);
                  }}>
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div key={idx} className={`voice-msg voice-msg-${msg.role}`}>
              <div className="voice-msg-avatar">{msg.role === "user" ? "👤" : "🛡️"}</div>
              <div className="voice-msg-content">
                <div className="voice-msg-header">
                  <span>{msg.role === "user" ? "You" : "Trinetra"}</span>
                  {msg.mode && msg.mode !== "chat" && (
                    <span className={`voice-msg-mode-tag voice-mode-tag-${msg.mode}`}>{msg.mode}</span>
                  )}
                  {msg.role === "assistant" && msg.ai_provider && (
                    <span className="voice-msg-provider">{msg.ai_provider}</span>
                  )}
                </div>
                <p className="voice-msg-text">{msg.text}</p>
                {/* Step instruction card for guided mode */}
                {msg.mode === "guided" && msg.step_instruction && !msg.is_complete && (
                  <div className="voice-step-card">
                    <div className="voice-step-card-label">Current Step</div>
                    <div className="voice-step-card-text">{msg.step_instruction}</div>
                    <div className="voice-step-card-actions">
                      <button className="voice-step-done-btn" onClick={() => sendQuestion("Done. What's next?")} disabled={loading}>
                        Done - Next Step
                      </button>
                    </div>
                  </div>
                )}
                {/* Verification result card */}
                {msg.mode === "verification" && (
                  <div className={`voice-verify-card ${msg.is_resolved ? "voice-verify-ok" : "voice-verify-warn"}`}>
                    <span className="voice-verify-icon">{msg.is_resolved ? "✅" : "⚠️"}</span>
                    <span>{msg.is_resolved ? "Threat Resolved" : `${msg.remaining_alerts || 0} alerts remaining`}</span>
                  </div>
                )}
                {msg.role === "assistant" && msg.audio_base64 && (
                  <button className={`voice-msg-replay ${playing ? "voice-playing-small" : ""}`}
                    onClick={() => replayMessage(msg)} title={playing ? "Stop" : "Replay audio"}>
                    {playing ? "⏹ Stop" : "🔊 Replay"}
                  </button>
                )}
              </div>
            </div>
          ))
        )}
        {loading && (
          <div className="voice-msg voice-msg-assistant">
            <div className="voice-msg-avatar">🛡️</div>
            <div className="voice-msg-content">
              <div className="voice-typing"><span className="voice-typing-dot" /><span className="voice-typing-dot" /><span className="voice-typing-dot" /></div>
            </div>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Status bar */}
      {status && <div className="voice-status-bar">{status}</div>}

      {/* Quick actions */}
      <div className="voice-quick-actions">
        <button className="voice-quick-btn" onClick={summarizeThreats} disabled={loading}>🛡️ Summarize</button>
        <button className="voice-quick-btn" onClick={startInvestigation} disabled={loading}>🔍 Investigate</button>
        {hasThreats && <button className="voice-quick-btn" onClick={() => switchMode("guided")} disabled={loading}>🔧 Fix It</button>}
        {guidedState.active && <button className="voice-quick-btn voice-verify-btn" onClick={startVerification} disabled={loading}>✅ Verify</button>}
        {playing && <button className="voice-quick-btn voice-stop-btn" onClick={stopAudio}>⏹ Stop</button>}
      </div>

      {/* Input area with microphone */}
      <form className="voice-input-form" onSubmit={askQuestion}>
        <button type="button"
          className={`voice-mic-btn ${listening ? "voice-mic-active" : ""}`}
          onClick={listening ? stopListening : startListening}
          disabled={loading || !SpeechRecognition}
          title={listening ? "Stop listening" : "Speak your question"}>
          {listening ? "🔴" : "🎤"}
        </button>
        <input ref={inputRef} className="voice-input" value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder={
            mode === "guided"
              ? (selectedLang === "hi" ? "Step complete bolne ke liye mic dabayein..." : "Say 'done' when step is complete...")
              : selectedLang === "hi"
              ? "Suraksha ke baare mein poochho ya mic dabao..."
              : "Ask about security, threats, or say 'investigate'..."
          }
          disabled={loading} />
        <button type="submit" className="voice-send-btn" disabled={loading || !question.trim()}>
          {loading ? "..." : "▶"}
        </button>
      </form>

      <div className="voice-footer">
        <span>AI Security Analyst</span>
        <strong>{langList.length} Languages</strong>
        <span>{mode === "guided" ? "Guided Mode" : mode === "investigate" ? "Investigation" : "Conversational"}</span>
      </div>
    </article>
  );
});

export default VoiceAlertPlayer;
