import { useState, useRef, useEffect, forwardRef, useImperativeHandle, useCallback } from "react";

const LANG_LOCALES = {
  en: "en-IN",
  hi: "hi-IN",
  mr: "mr-IN",
  gu: "gu-IN",
  te: "te-IN",
  ta: "ta-IN",
  kn: "kn-IN",
  ml: "ml-IN",
  bn: "bn-IN",
  pa: "pa-IN",
  or: "or-IN",
  as: "as-IN",
};

const VoiceAlertPlayer = forwardRef(function VoiceAlertPlayer({ languages, voiceAvailable, geminiAnalysis, overview, alerts }, ref) {
  const [selectedLang, setSelectedLang] = useState("en");
  const [playing, setPlaying] = useState(false);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [spokenText, setSpokenText] = useState("");

  const audioRef = useRef(null);
  const keepAliveRef = useRef(null);

  const useBrowserTTS = !voiceAvailable;
  const activeTTSProvider = (selectedLang === "en" || selectedLang === "hi")
    ? (voiceAvailable ? "Sarvam AI" : "Browser TTS")
    : "Browser TTS";

  useImperativeHandle(ref, () => ({
    play: () => summarizeThreats(),
  }));

  useEffect(() => {
    const warmTTS = () => {
      window.speechSynthesis.getVoices();
      document.removeEventListener("click", warmTTS);
      document.removeEventListener("keydown", warmTTS);
    };
    document.addEventListener("click", warmTTS, { once: true });
    document.addEventListener("keydown", warmTTS, { once: true });
    return () => {
      document.removeEventListener("click", warmTTS);
      document.removeEventListener("keydown", warmTTS);
    };
  }, []);

  const findBrowserVoice = useCallback((langCode) => {
    const voices = window.speechSynthesis.getVoices();
    if (!voices.length) return null;
    let voice = voices.find((v) => v.lang === langCode);
    if (voice) return voice;
    const langPrefix = langCode.split("-")[0];
    voice = voices.find((v) => v.lang.startsWith(langPrefix));
    if (voice) return voice;
    voice = voices.find((v) => v.lang.startsWith("hi"));
    if (voice) return voice;
    voice = voices.find((v) => v.lang === "en-IN");
    if (voice) return voice;
    voice = voices.find((v) => v.lang.startsWith("en"));
    if (voice) return voice;
    return voices[0] || null;
  }, []);

  const playAudio = useCallback((text, audioBase64, format, provider, langCode) => {
    stopAudio();
    setPlaying(true);
    if (audioBase64 && format !== "browser-fallback") {
      const mimeType = format === "mp3" ? "audio/mpeg" : "audio/wav";
      const audio = new Audio(`data:${mimeType};base64,${audioBase64}`);
      audioRef.current = audio;
      audio.onended = () => { setPlaying(false); setStatus(""); };
      audio.onerror = () => { setPlaying(false); setStatus("Audio playback failed"); };
      audio.play().catch(() => { setPlaying(false); setStatus("Audio autoplay blocked"); });
      setStatus(`Playing via ${provider}`);
    } else {
      const resolvedLang = langCode || LANG_LOCALES[selectedLang] || "en-IN";
      const doSpeak = () => {
        window.speechSynthesis.cancel();
        if (keepAliveRef.current) clearInterval(keepAliveRef.current);
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = resolvedLang;
        utterance.rate = 0.9;
        utterance.pitch = 1.0;
        utterance.volume = 1.0;
        const voice = findBrowserVoice(resolvedLang);
        if (voice) {
          utterance.voice = voice;
          utterance.lang = voice.lang;
        }
        utterance.onstart = () => {
          setStatus(`Speaking (${voice?.lang || resolvedLang})`);
          keepAliveRef.current = setInterval(() => {
            if (window.speechSynthesis.speaking && !window.speechSynthesis.paused) {
              window.speechSynthesis.pause();
              window.speechSynthesis.resume();
            }
          }, 10000);
        };
        utterance.onend = () => {
          if (keepAliveRef.current) clearInterval(keepAliveRef.current);
          setPlaying(false);
          setStatus("");
        };
        utterance.onerror = (e) => {
          if (keepAliveRef.current) clearInterval(keepAliveRef.current);
          setPlaying(false);
          if (e.error !== "canceled") setStatus(`TTS error: ${e.error}`);
        };
        setTimeout(() => window.speechSynthesis.speak(utterance), 100);
      };
      if (window.speechSynthesis.getVoices().length > 0) {
        doSpeak();
      } else {
        window.speechSynthesis.onvoiceschanged = () => {
          doSpeak();
          window.speechSynthesis.onvoiceschanged = null;
        };
        setTimeout(() => {
          if (window.speechSynthesis.getVoices().length === 0) doSpeak();
        }, 1000);
      }
      setStatus(`Browser TTS (${resolvedLang})`);
    }
  }, [selectedLang, findBrowserVoice]);

  function stopAudio() {
    if (keepAliveRef.current) clearInterval(keepAliveRef.current);
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
      if (keepAliveRef.current) clearInterval(keepAliveRef.current);
      window.speechSynthesis?.cancel();
      if (audioRef.current) audioRef.current.pause();
    };
  }, []);

  async function summarizeThreats() {
    if (loading) return;
    setLoading(true);
    setStatus("Analyzing threats...");

    const score = overview?.score ?? 0;
    const alertCount = alerts?.length ?? 0;

    try {
      const geminiText = geminiAnalysis?.analysis || "";
      const summaryText = geminiText
        ? `Gemini analysis summary: ${geminiText.slice(0, 500)}. Overall risk score is ${score} with ${alertCount} alerts.`
        : `Current security status: Risk score is ${score} with ${alertCount} alerts. No Gemini analysis available.`;

      const data = await fetch("/api/voice/speak", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: summaryText, language: selectedLang }),
      }).then((r) => r.json());

      const responseText = data.response || data.text || summaryText;
      setSpokenText(responseText);
      playAudio(responseText, data.audio_base64, data.format, data.provider, data.lang_code);
    } catch {
      setStatus("Summary unavailable — playing via browser TTS");

      const fallbackText = geminiAnalysis?.analysis
        ? `Gemini analysis: ${geminiAnalysis.analysis.slice(0, 300)}. Risk score is ${score}.`
        : `Security summary not available. Risk score is ${score} with ${alertCount} alerts.`;

      setSpokenText(fallbackText);
      playAudio(fallbackText, null, "browser-fallback", "Browser TTS", selectedLang);
    } finally {
      setLoading(false);
    }
  }

  const langList = languages || [
    { code: "en", label: "English", native: "English" },
    { code: "hi", label: "Hindi", native: "हिन्दी" },
    { code: "mr", label: "Marathi", native: "मराठी" },
    { code: "gu", label: "Gujarati", native: "ગુજરાતી" },
    { code: "te", label: "Telugu", native: "తెలుగు" },
  ];

  return (
    <article className="panel panel-voice">
      <div className="panel-header">
        <div>
          <span className="eyebrow">AI Security Analyst — Voice Summary</span>
          <h2>Trinetra Voice</h2>
        </div>
        <div className="voice-header-badges">
          <span className={`ai-chip ${activeTTSProvider === "Browser TTS" ? "voice-chip-fallback" : ""}`}>
            {activeTTSProvider}
          </span>
        </div>
      </div>

      <p className="voice-desc">
        Summarizes Gemini threat analysis in your preferred language.
      </p>

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

      <div className="voice-controls">
        <button className="voice-play-btn" onClick={summarizeThreats} disabled={loading}>
          {loading ? "⟳ Summarizing..." : playing ? "🔊 Playing..." : "🎙️ Summarize Threats"}
        </button>
        {playing && (
          <button className="voice-play-btn voice-playing" onClick={stopAudio}>
            ⏹ Stop
          </button>
        )}
      </div>

      {status && <div className="voice-status">{status}</div>}

      {spokenText && (
        <div className="voice-spoken-text">
          <span className="eyebrow">Last Summary</span>
          <p>{spokenText}</p>
        </div>
      )}

      <div className="voice-footer">
        <span>AI Security Analyst</span>
        <strong>{langList.length} Languages</strong>
        <span>Voice Summary</span>
      </div>
    </article>
  );
});

export default VoiceAlertPlayer;
