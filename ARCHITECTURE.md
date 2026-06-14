# Trinetra Sentinel Architecture

**Desktop EDR Platform** — Electron + React + FastAPI + SQLite

---

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    ELECTRON SHELL (main.cjs)                      │
│  - Spawns Python backend as child process                         │
│  - Waits for backend health check (/api/overview)                 │
│  - Opens BrowserWindow loading http://127.0.0.1:8000              │
│  - Cleans up backend on app quit                                  │
├──────────────────────────────────────────────────────────────────┤
│                    REACT DASHBOARD (Vite)                          │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ Security  │ │ Endpoint     │ │ Stat     │ │ Live Threat    │  │
│  │ Index     │ │ Status       │ │ Cards    │ │ Feed           │  │
│  └──────────┘ └──────────────┘ └──────────┘ └────────────────┘  │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ USB      │ │ AI Analysis  │ │ Threat   │ │ Alert Timeline │  │
│  │ Security │ │ + Gemini     │ │ Summary  │ │                │  │
│  └──────────┘ └──────────────┘ └──────────┘ └────────────────┘  │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ Voice    │ │ Module       │ │ Log      │ │ Collector      │  │
│  │ Assis-   │ │ Matrix       │ │ Detection│ │ Health         │  │
│  │ tant     │ │              │ │          │ │                │  │
│  └──────────┘ └──────────────┘ └──────────┘ └────────────────┘  │
│  ┌──────────────────┐ ┌────────────────────┐                     │
│  │ Active Processes │ │ System Activity    │                     │
│  └──────────────────┘ └────────────────────┘                     │
└────────────────────────┬─────────────────────────────────────────┘
                         │ WebSocket (live) + REST (polling)
┌────────────────────────▼─────────────────────────────────────────┐
│                    FASTAPI BACKEND (uvicorn)                       │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              SystemMonitor (3-second loop)                │    │
│  │  1. collect_snapshot() → CPU, RAM, disk, net, temps      │    │
│  │  2. scan_processes() → detect new/stopped apps           │    │
│  │  3. active_processes() → resource ranking                │    │
│  │  4. telemetry.poll() → all collectors                    │    │
│  │  5. push logs via WebSocket                              │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Telemetry Collectors (backend/telemetry.py)              │    │
│  │  ┌────────────────┐ ┌──────────────┐ ┌────────────────┐  │    │
│  │  │ SecurityEvent  │ │ USBCollector │ │ RegistryCollect│  │    │
│  │  │ Collector      │ │ (WMI + API)  │ │ or (Run keys)  │  │    │
│  │  └────────────────┘ └──────────────┘ └────────────────┘  │    │
│  │  ┌────────────────┐ ┌──────────────────────────────┐     │    │
│  │  │ ApplicationLog │ │ RansomwareEventHandler       │     │    │
│  │  │ Collector      │ │ (watchdog file watcher)      │     │    │
│  │  └────────────────┘ └──────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Detection & Analysis Engines (backend/engines/)          │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────┐   │    │
│  │  │ risk.py    │ │ ai_attrib  │ │ code_protection.py │   │    │
│  │  │ (scoring)  │ │ ution.py   │ │ (file bursts)      │   │    │
│  │  └────────────┘ └────────────┘ └────────────────────┘   │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────┐   │    │
│  │  │ usb_       │ │ resource_  │ │ system_activity.py │   │    │
│  │  │ security.py│ │ analyzer.py│ │                    │   │    │
│  │  └────────────┘ └────────────┘ └────────────────────┘   │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────┐   │    │
│  │  │ ai_analysis│ │ local_     │ │ performance_       │   │    │
│  │  │ .py        │ │ analytics  │ │ optimizer.py       │   │    │
│  │  └────────────┘ └────────────┘ └────────────────────┘   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  AI Modules (backend/ai/)                                 │    │
│  │  ┌──────────────┐ ┌────────────┐ ┌──────────────────┐   │    │
│  │  │ gemini_      │ │ sarvam_    │ │ mitre_mapper.py  │   │    │
│  │  │ analyzer.py  │ │ voice.py   │ │ (ATT&CK mapping) │   │    │
│  │  └──────────────┘ └────────────┘ └──────────────────┘   │    │
│  │  ┌──────────────┐ ┌────────────┐ ┌──────────────────┐   │    │
│  │  │ gemini_rate_ │ │ gemini_    │ │ google_tts.py    │   │    │
│  │  │ limiter.py   │ │ cache.py   │ │ edge_tts_prov...│   │    │
│  │  └──────────────┘ └────────────┘ └──────────────────┘   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────┐ ┌──────────────────┐ ┌────────────────────┐   │
│  │ database.py  │ │ notifications.py │ │ detection.py       │   │
│  │ (SQLite)     │ │ (WPF popups)     │ │ (ThreatEngine)     │   │
│  └──────────────┘ └──────────────────┘ └────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Backend Modules

### Core

| Module | Path | Role |
|--------|------|------|
| `main.py` | `backend/main.py` | FastAPI app: all REST endpoints, WebSocket, lifespan, module inventory |
| `monitor.py` | `backend/monitor.py` | `SystemMonitor` — main loop (3s interval), snapshot, process scan, telemetry poll |
| `detection.py` | `backend/detection.py` | `ThreatEngine` — event creation, process inspection, correlation, `AnomalyDetector` (Isolation Forest) |
| `database.py` | `backend/database.py` | SQLite wrapper for events and system_snapshots tables |
| `telemetry.py` | `backend/telemetry.py` | `TelemetryManager` + all collectors (Security, USB, Registry, Application logs, File watchdog) |
| `notifications.py` | `backend/notifications.py` | WPF popup + WinForms balloon notifications with severity cooldowns |

### Detection Engines (`backend/engines/`)

| Engine | File | Purpose |
|--------|------|---------|
| Risk Scoring | `risk.py` | 0–100 scoring, severity mapping, `compute_risk_score()`, `build_remediations()` with immediate/investigate/prevent steps |
| AI Attribution | `ai_attribution.py` | Detects AI coding tools (Cursor, Claude, Copilot, Cline, Roo, Windsurf, Aider) and dangerous commands |
| AI Analysis | `ai_analysis.py` | Local algorithm-based threat summary, findings, recommendations, interactive Q&A system |
| Code Protection | `code_protection.py` | Mass deletion/rename/modification burst detection (watchdog-based) |
| USB Security | `usb_security.py` | USB scan: autorun, executables, scripts, hidden files, known malware hashes, PE packers, malicious script patterns |
| Resource Analyzer | `resource_analyzer.py` | Per-process CPU/RAM/disk I/O aggregation and ranking |
| System Activity | `system_activity.py` | Process start/stop tracking with name-based deduplication |
| Local Analytics | `local_analytics.py` | Log aggregation, 10 attack chain patterns, per-incident scoring, anomaly detection, timeline, markdown report |
| Performance Optimizer | `performance_optimizer.py` | Identifies safe-to-kill resource-heavy processes with Windows-critical protection |

### AI Modules (`backend/ai/`)

| Module | File | Purpose |
|--------|------|---------|
| Gemini Analyzer | `gemini_analyzer.py` | Gemini API: threat analysis, alert explanation, incident reports, conversation, investigation, guided remediation |
| Sarvam Voice | `sarvam_voice.py` | 12-language TTS with multi-provider fallback (Google Cloud TTS → Edge TTS → Sarvam → Browser) |
| MITRE Mapper | `mitre_mapper.py` | Rule-based event → MITRE ATT&CK technique mapping (20+ techniques) |
| Gemini Rate Limiter | `gemini_rate_limiter.py` | API call rate limiter |
| Gemini Cache | `gemini_cache.py` | Response cache for Gemini |
| Google TTS | `google_tts.py` | Google Cloud Text-to-Speech provider |
| Edge TTS Provider | `edge_tts_provider.py` | Edge TTS provider |

---

## Frontend Components

| Component | File | Description |
|-----------|------|-------------|
| App | `App.jsx` | Dashboard layout composing all sections |
| Header | `Header.jsx` | App title, monitoring status, clock |
| SecurityIndex | `SecurityIndex.jsx` | Risk score gauge (0–100) with severity badge |
| EndpointStatus | `EndpointStatus.jsx` | CPU, RAM, disk, network, temps |
| StatCards | `StatCards.jsx` | Alert counts, AI events, USB events |
| LiveThreatFeed | `LiveThreatFeed.jsx` | Real-time alert feed with severity colors |
| USBSecurity | `USBSecurity.jsx` | USB device list with scan status |
| AIAnalysis | `AIAnalysis.jsx` | Local AI report + interactive Q&A |
| ThreatSummary | `ThreatSummary.jsx` | Categorized alert counts |
| AlertTimeline | `AlertTimeline.jsx` | Bar chart of alert frequency |
| AIThreatSummary | `AIThreatSummary.jsx` | Gemini analysis + MITRE mapping |
| VoiceAlertPlayer | `VoiceAlertPlayer.jsx` | Multilingual voice alert player |
| ModuleMatrix | `ModuleMatrix.jsx` | 13+ engine status cards |
| LogDetection | `LogDetection.jsx` | Windows Event Log stream table |
| CollectorHealth | `CollectorHealth.jsx` | Telemetry source status indicators |
| ActiveProcesses | `ActiveProcesses.jsx` | Ranked process list |
| SystemActivity | `SystemActivity.jsx` | App open/close history |
| ExplainAlertModal | `ExplainAlertModal.jsx` | Gemini-powered alert explanation |
| Toast | `Toast.jsx` | In-app notification popups |

---

## Electron App

| File | Role |
|------|------|
| `frontend/electron/main.cjs` | Main process: spawns Python backend, creates BrowserWindow, lifecycle management |
| `frontend/electron/launch.cjs` | Launch helper: spawns Electron with proper env |
| `frontend/electron/preload.cjs` | Preload script (context bridge) |

---

## REST API Endpoints

```
GET  /api/overview              Dashboard overview (score, severity, categories, telemetry)
GET  /api/alerts                Visible alerts (deduped, noise-filtered)
GET  /api/snapshots             System resource snapshot history
GET  /api/processes             Active processes ranked by resource usage
GET  /api/activity              Live activity feed (process + USB)
GET  /api/usb/activity          USB-specific activity history
GET  /api/usb/status            Connected USB devices with scan results
GET  /api/modules               Engine module inventory with status
GET  /api/ai-analysis           Local AI analysis report
POST /api/ai-question           Ask questions about system state
GET  /api/telemetry             Collector health status
GET  /api/logs/recent           Recent Windows event log entries
POST /api/reset                 Clear all events
GET  /api/report.csv            Download CSV incident report
GET  /api/analytics/report      Local analytics report (no Gemini dependency)

  --- AI / Gemini ---
GET  /api/gemini/status         Gemini API availability
GET  /api/gemini/analyze        Gemini-powered threat analysis
POST /api/gemini/explain        Explain why an alert was generated
GET  /api/gemini/incident-report AI-assisted incident report
GET  /api/mitre-mapping         MITRE ATT&CK mapping for current events

  --- Voice / TTS ---
POST /api/voice/speak           Text-to-speech synthesis
POST /api/voice/alert           Convert alert to voice notification
POST /api/voice/analysis        Convert analysis to voice
POST /api/voice/report          Multilingual voice report pipeline
POST /api/voice/converse        Conversational AI voice (ChatGPT Voice style)
POST /api/voice/investigate     Deep investigation with voice
POST /api/voice/guide           Guided step-by-step remediation
POST /api/voice/verify          Verify threat resolution
GET  /api/voice/languages       Supported voice languages

  --- Performance Optimizer ---
GET  /api/optimizer/scan        Scan optimizable processes
POST /api/optimizer/kill        Kill a single process by PID
POST /api/optimizer/kill-all    Kill all safe-rated processes
```

### WebSocket

```
WS   /ws                        Real-time push: connected, alert, snapshot, processes, activity, logs, reset
```

---

## Data Flow

### Real-time Loop (every 3s)
1. **Snapshot** → CPU/RAM/disk/net → stored in SQLite + broadcast
2. **Process scan** → detect new/stopped apps, inspect for threats
3. **Resource collection** → aggregate process resources → broadcast
4. **Telemetry poll** → Security/System/Application/Setup/PowerShell logs, USB, registry, file system
5. **Log push** → new log entries via WebSocket

### Alert Pipeline
1. Engine detects event → `ThreatEngine.create_event()` (score + severity)
2. Time-based dedup (120s cooldown per event_type + title + process)
3. Stored in SQLite
4. Broadcast via WebSocket to frontend
5. USB events → also published to USB activity feed
6. High/critical → desktop WPF popup notification
7. `ThreatEngine.correlate()` → cross-category intrusion pattern check
8. Attack chain detection via `LocalAnalyticsEngine`

### Noise Filtering (display)
- Hidden types: `system_warning`, `usb_removed`, `usb_scan_clean`, `process_started/stopped`, `normal_activity`
- Score threshold: 20 (unless high/critical severity)
- Dedup by (event_type, title, summary[:120])
