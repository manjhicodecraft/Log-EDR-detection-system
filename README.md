# Trinetra Sentinel

**Desktop-native Endpoint Detection & Response (EDR)** — An offline-first Windows EDR
application built with Electron + React + FastAPI. Collects real endpoint telemetry,
detects threats using rule-based and ML engines, and provides a SOC-style desktop
dashboard with voice-enabled AI analysis.

---

## Quick Start (Desktop App)

### One-click launcher:

```text
run_trinetra_desktop.bat
```

This installs dependencies (Python venv + npm), starts the backend, builds the React
dashboard, and launches the Electron desktop window.

### Manual:

```powershell
pip install -r requirements.txt
cd frontend && npm install && npm run electron
```

The Electron app (`frontend/electron/main.cjs`) auto-starts the Python FastAPI backend,
waits for it to be ready, and opens the Trinetra Sentinel desktop window.

> **Tip:** `run_trinetra.bat` (browser mode) is also available for quick testing without
> Electron — it opens `http://127.0.0.1:8000` in your default browser.

---

## Capabilities

### 13+ Detection & Analysis Engines

| Engine | Function |
|--------|----------|
| **System Activity Engine** | Tracks process start/stop events (name-based dedup) |
| **Resource Analyzer** | CPU, RAM, disk I/O, network connections per process |
| **AI Attribution Engine** | Detects Cursor, Claude Code, Copilot, Cline, Roo, Windsurf, Aider in process chains |
| **Code Protection Engine** | Mass deletion/rename/modification burst detection via watchdog |
| **USB Security Engine** | Auto-scan for autorun, executables, scripts, hidden files, known malware hashes |
| **Threat Detection Engine** | Encoded PowerShell, AI-origin shells, high CPU/RAM, anomaly rules |
| **Log Correlation Engine** | Cross-category intrusion pattern detection (3+ categories in 5 min) |
| **Risk Scoring Engine** | 0–100 scoring with time-decay, severity mapping, remediation templates |
| **AI Analysis Module** | Local algorithm-based threat summary, findings, recommendations, interactive Q&A |
| **Local Analytics Engine** | Log aggregation, attack chain detection (10 chains), incident timeline, markdown reports |
| **Gemini Threat Intelligence** | Google Gemini API integration with severity gating, rate limiting, response cache |
| **MITRE ATT&CK Mapper** | Rule-based mapping of events → MITRE techniques and tactics |
| **Multilingual Voice Assistant** | 12-language TTS via Sarvam AI, Google Cloud TTS, Edge TTS — with conversation, investigation, guided remediation |
| **Performance Optimizer** | Identifies safe-to-kill resource-heavy processes with critical-process protection |

### Telemetry Sources

- Windows Security Event Log (failed logins, account lockouts, brute-force detection)
- Windows System/Application/Setup/PowerShell Event Logs (crashes, service failures, threat keywords)
- USB storage device insertion/removal via WMI + Windows API
- Startup registry monitoring (`HKCU\...\Run`)
- File system watchdog (Desktop, Documents, Downloads) — ransomware behavior detection

### AI & Intelligence

- **Gemini-powered** threat analysis, alert explanation, incident reports, conversational voice interface
- **Local AI analysis** — 100% offline summarization with dynamic Q&A routing
- **12-language voice assistant** with multi-provider TTS fallback
- **MITRE ATT&CK** technique mapping for all detected events
- **Attack chain detection** — 10 predefined attack progression patterns

### Notifications

- **WPF desktop popups** — bottom-right corner with severity-colored borders
- **WinForms balloon tips** — fallback if WPF unavailable
- **System alert sounds** for critical/high severity
- **Severity-based cooldowns** to prevent notification flooding

---

## Architecture

```
┌──────────────────────────────────────────────┐
│           ELECTRON DESKTOP APP                │
│  ┌────────────────────────────────────────┐   │
│  │         React Dashboard (Vite)         │   │
│  │  Endpoint Status  │  Live Threat Feed  │   │
│  │  USB Security     │  AI Analysis       │   │
│  │  Process Viewer   │  Voice Assistant   │   │
│  └────────────────┬───────────────────────┘   │
│                   │ WebSocket + REST           │
├───────────────────┼──────────────────────────┤
│                   ▼                            │
│          FastAPI Backend (uvicorn)             │
│  ┌────────────────────────────────────────┐   │
│  │  SystemMonitor (3s loop)               │   │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐  │   │
│  │  │Telemetry │ │ Process  │ │Resource│  │   │
│  │  │Collectors│ │ Scanner  │ │Analyzer│  │   │
│  │  └──────────┘ └──────────┘ └────────┘  │   │
│  └────────────────────────────────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │  Threat  │ │  AI &    │ │SQLite + Log  │  │
│  │ Engines  │ │ Analytics│ │   Storage    │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
└──────────────────────────────────────────────┘
```

---

## Development

```powershell
# Backend (separate terminal)
python -m backend                                    # http://127.0.0.1:8000

# Frontend dev with hot-reload (separate terminal)
cd frontend && npm install && npm run dev             # http://127.0.0.1:5173

# Electron dev (builds frontend, starts backend, opens desktop window)
cd frontend && npm run electron

# Production build
cd frontend && npm run build
```

---

## Requirements

- Windows 10/11 (primary target; Linux/macOS limited)
- Python 3.10+
- Node.js 18+
- Optional: `GEMINI_API_KEY` in `.env` for Gemini threat intelligence

---

## Notes

- Windows Security Log visibility depends on current user's Event Log permissions.
- The **Collector Health** panel reports whether each telemetry source is active or limited.
- Set `TRINETRA_WATCH_PATHS` with semicolon-separated folders to override default Desktop,
  Documents, and Downloads file watchers.
- Set `GEMINI_API_KEY`, `GEMINI_MODEL`, `GOOGLE_APPLICATION_CREDENTIALS`, `SARVAM_API_KEY`
  in `.env` for AI features.
