"""
Sarvam AI Voice Assistant Module
---------------------------------
Converts Gemini-generated analyses and alert explanations into
multilingual voice notifications using Sarvam AI's Text-to-Speech API.

Supported languages: English, Hindi, Telugu
Falls back to browser-native speech synthesis if API unavailable.
"""

from __future__ import annotations

import base64
import io
import os
from datetime import datetime, timezone


def _get_env(key: str, default: str = "") -> str:
    value = os.environ.get(key, "")
    if value:
        return value
    env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    if k.strip() == key:
                        return v.strip()
    except Exception:
        pass
    return default


try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _requests = None
    _HAS_REQUESTS = False


# ── Language codes for Sarvam AI ──
SARVAM_LANGUAGES = {
    "en": "en-IN",
    "hi": "hi-IN",
    "te": "te-IN",
}

# ── Pre-built translations for common alerts ──
ALERT_TRANSLATIONS = {
    "hi": {
        "critical_threat": "Gambhir suraksha khatra detect hua hai. Turant investigation karne ki salah di jaati hai.",
        "high_threat": "Uchch star ka suraksha khatra detect hua hai. Kripya alert ki samiksha karein.",
        "medium_threat": "Madhyam star ka suraksha alert detect hua hai. Nigraani ki salah di jaati hai.",
        "low_threat": "Nimn star ka suraksha event detect hua hai. Koi turant karvayi ki zarurat nahi.",
        "usb_detected": "USB device detect hui hai. Kripya scan karein pehle upyog karne se.",
        "ransomware": "Ransomware jaisi gatividhi detect hui hai. Turant network se disconnect karein.",
        "failed_login": "Bahut se asafal login prayas detect hue hain. Brute force attack sambhav hai.",
        "system_normal": "System surakshit hai. Koi khatra detect nahi hua.",
        "incident_generated": "Incident report taiyar ki gayi hai. Kripya review karein.",
    },
    "te": {
        "critical_threat": "Tivramaina bhadratha muppu gurthinchabadindi. Dayachesi ventane parishilinchandi.",
        "high_threat": "High level bhadratha muppu gurthinchabadindi. Dayachesi alert ni parishilinchandi.",
        "medium_threat": "Medium level bhadratha alert gurthinchabadindi. Paryaveekshana salah isthunnamu.",
        "low_threat": "Low level bhadratha event gurthinchabadindi. Ventane charya avasaram ledu.",
        "usb_detected": "USB device gurthinchabadindi. Vadakamundu scan cheyandi.",
        "ransomware": "Ransomware laanti karyam gurthinchabadindi. Ventane network nunchi disconnect cheyandi.",
        "failed_login": "Chala failed login prayatnaalu gurthinchabaadayaayi. Brute force attack ayye avakaasam undi.",
        "system_normal": "System surakshitamga undi. Ee muppu ledu.",
        "incident_generated": "Incident report sidham chesamu. Dayachesi parishilinchandi.",
    },
}

# ── Sarvam AI TTS API endpoint ──
SARVAM_TTS_URL = "https://api.sarvam.ai/text-to-speech"


class SarvamVoiceModule:
    """Multilingual voice notification generator using Sarvam AI TTS."""

    def __init__(self):
        self._api_key = _get_env("SARVAM_API_KEY")
        self._available = _HAS_REQUESTS and bool(self._api_key)
        self._default_voice = _get_env("SARVAM_DEFAULT_VOICE", "meera")

    @property
    def available(self) -> bool:
        return self._available

    def translate_alert(self, alert: dict, language: str = "en") -> str:
        """Convert an alert to a translated text message."""
        if language == "en":
            severity = alert.get("severity", "low")
            title = alert.get("title", "Security event")
            summary = alert.get("summary", "")[:120]
            return f"{severity.upper()} alert: {title}. {summary}"

        translations = ALERT_TRANSLATIONS.get(language, ALERT_TRANSLATIONS["hi"])
        severity = alert.get("severity", "low")
        event_type = alert.get("event_type", "")

        if event_type == "ransomware_activity":
            return translations["ransomware"]
        if event_type in ("failed_login", "account_lockout"):
            return translations["failed_login"]
        if "usb" in event_type:
            return translations["usb_detected"]

        if severity == "critical":
            return translations["critical_threat"]
        if severity == "high":
            return translations["high_threat"]
        if severity == "medium":
            return translations["medium_threat"]
        return translations["low_threat"]

    def translate_analysis(self, analysis_text: str, language: str = "en") -> str:
        """Create a short voice-friendly summary from a full Gemini analysis.

        Strips markdown, extracts the most important sentences (Executive Summary
        + first bullet of Technical Analysis), and keeps the result under ~200 words
        so Sarvam TTS produces clear, natural audio.
        """
        import re

        if not analysis_text:
            return "No analysis available."

        # ── Step 1: Strip all markdown ──
        clean = analysis_text
        clean = re.sub(r"#{1,6}\s*", "", clean)        # ## headers
        clean = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)  # **bold**
        clean = re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)       # inline/block code
        clean = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)  # [links](url)
        clean = re.sub(r"^\s*[-*+]\s+", "", clean, flags=re.MULTILINE)  # bullet markers
        clean = re.sub(r"^\s*\d+\.\s+", "", clean, flags=re.MULTILINE)  # numbered lists

        # ── Step 1b: Remove known section titles so they don't leak into voice ──
        section_titles = [
            "Executive Summary", "Technical Analysis", "Potential Impact",
            "MITRE ATT&CK Coverage", "Recommended Actions", "Conclusion",
            "Incident Overview", "Timeline Summary", "Risk Assessment",
            "MITRE ATT&CK References", "Recommended Mitigation Steps",
        ]
        for title in section_titles:
            clean = re.sub(re.escape(title), "", clean, flags=re.IGNORECASE)

        clean = re.sub(r"\s+", " ", clean).strip()

        # ── Step 2: Split into sentences ──
        # Clean double periods left by removed section titles
        clean = re.sub(r"\.{2,}", ".", clean)
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", clean) if len(s.strip()) > 10]

        # ── Step 3: Prioritise Executive Summary sentences ──
        #    Gemini output starts with "## Executive Summary" so the first 2-3
        #    sentences after stripping are the high-level overview — perfect for voice.
        priority = sentences[:4]  # ~2-3 meaningful sentences from summary

        # ── Step 4: Cap at ~180 words so audio stays short ──
        words, result = 0, []
        for s in priority:
            wc = len(s.split())
            if words + wc > 180:
                break
            result.append(s)
            words += wc

        short_summary = " ".join(s.rstrip(".") for s in result).rstrip(". ") + "."

        # ── Step 5: For non-English, translate the short summary ──
        if language == "en":
            return short_summary

        translations = ALERT_TRANSLATIONS.get(language, ALERT_TRANSLATIONS["hi"])
        lower = analysis_text.lower()
        if "critical" in lower or "ransomware" in lower:
            return translations["critical_threat"]
        if "high" in lower:
            return translations["high_threat"]
        if "usb" in lower:
            return translations["usb_detected"]
        if "failed login" in lower or "brute force" in lower:
            return translations["failed_login"]
        return translations["system_normal"]

    def synthesize_speech(self, text: str, language: str = "en") -> dict:
        """Generate speech audio using Sarvam AI TTS API.

        Returns:
            dict with:
              - audio_base64: base64-encoded audio (WAV or MP3)
              - format: audio format
              - language: language code
              - text: the text spoken
              - provider: "sarvam" or "browser-fallback"
              - error: error message if failed
        """
        lang_code = SARVAM_LANGUAGES.get(language, "en-IN")

        if not self._available:
            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": "Sarvam API not configured — use browser speech synthesis instead",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        try:
            headers = {
                "api-subscription-key": self._api_key,
                "Content-Type": "application/json",
            }
            payload = {
                "inputs": [text],
                "target_language_code": lang_code,
                "speaker": self._default_voice,
            }
            response = _requests.post(
                SARVAM_TTS_URL,
                json=payload,
                headers=headers,
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                audio_b64 = data.get("audios", [None])[0] if isinstance(data, dict) else None
                if audio_b64:
                    return {
                        "audio_base64": audio_b64,
                        "format": "wav",
                        "language": language,
                        "lang_code": lang_code,
                        "text": text,
                        "provider": "sarvam",
                        "error": None,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": f"Sarvam API returned status {response.status_code}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": f"Sarvam API error: {exc}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def speak_alert(self, alert: dict, language: str = "en") -> dict:
        """Full pipeline: translate alert -> synthesize speech."""
        text = self.translate_alert(alert, language)
        return self.synthesize_speech(text, language)

    def speak_analysis(self, analysis_text: str, language: str = "en") -> dict:
        """Full pipeline: summarize analysis -> synthesize speech."""
        text = self.translate_analysis(analysis_text, language)
        return self.synthesize_speech(text, language)

    def get_supported_languages(self) -> list[dict]:
        """Return list of supported languages for the frontend."""
        return [
            {"code": "en", "label": "English", "native": "English"},
            {"code": "hi", "label": "Hindi", "native": "हिन्दी"},
            {"code": "te", "label": "Telugu", "native": "తెలుగు"},
        ]
