# Trinetra Sentinel — Complete Application Report

**Version:** 1.0.0
**Platform:** Windows (Desktop EDR — Electron + React + FastAPI)
**Last Updated:** June 2026

---

## 1. Project Overview

Trinetra Sentinel is a **desktop-native Endpoint Detection and Response (EDR) application**
for Windows. It monitors endpoint activity in real-time, detects threats using rule-based
engines and ML anomaly detection, correlates events across multiple sources, and provides
risk scoring — all running locally. The desktop UI is built with Electron + React, and the
backend is a Python FastAPI server.

### Core Design Principles
- **Desktop-first:** Electron app with native window, auto-start backend, system tray
- **Offline-first:** No external APIs required for core detection. All analysis runs locally.
- **Real-time monitoring:** WebSocket-based live updates every ~3 seconds.
- **Lightweight:** SQLite storage, minimal dependencies, single-machine deployment.
- **Privacy-safe:** No telemetry sent to cloud. All data stays on the endpoint.

---

## 2. Technology Stack

### Backend
| Component | Technology | Version |
|-----------|-----------|---------|
| Web Framework | FastAPI | 0.115.6 |
| Server | Uvicorn | 0.34.0 |
| Process Monitoring | psutil | 6.1.1 |
| ML Anomaly Detection | scikit-learn (Isolation Forest) | 1.6.0 |
| Numerical Computing | numpy | 2.2.1 |
| Windows Event Logs | pywin32 | 308 |
| USB Device Discovery | WMI | 1.5.1 |
| File System Monitoring | watchdog | 6.0.0 |
| Database | SQLite | Built-in |
| Language | Python | 3.13 |

### Frontend & Desktop
| Component | Technology | Version |
|-----------|-----------|---------|
| Desktop Shell | Electron | 33.3.1 |
| UI Library | React | 19.0.0 |
| Build Tool | Vite | 6.0.5 |
| Real-time Updates | WebSocket | Native |
| Language | JavaScript (JSX) | ES Module |

---

## 3. Application Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    ELECTRON (main.cjs)                            │
│  - Spawns Python backend via child_process                        │
│  - Health-checks /api/overview before opening window              │
│  - Cleans up backend on app.quit()                                │
│  - Window: 1360x860, dark background, auto-hide menu bar          │
├──────────────────────────────────────────────────────────────────┤
│                    REACT DASHBOARD (Vite)                          │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Security │ │ Endpoint   │ │ Stat     │ │ Live Threat      │   │
│  │ Index    │ │ Status     │ │ Cards    │ │ Feed             │   │
│  └──────────┘ └────────────┘ └──────────┘ └──────────────────┘   │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ USB      │ │ AI Analysis│ │ Threat   │ │ Alert Timeline   │   │
│  │ Security │ │ + Gemini   │ │ Summary  │ │                  │   │
│  └──────────┘ └────────────┘ └──────────┘ └──────────────────┘   │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Voice    │ │ Module     │ │ Log      │ │ Collector        │   │
│  │ Assis-   │ │ Matrix     │ │ Detection│ │ Health           │   │
│  │ tant     │ │            │ │          │ │                  │   │
│  └──────────┘ └────────────┘ └──────────┘ └──────────────────┘   │
│  ┌────────────────┐ ┌────────────────────┐                        │
│  │ Active         │ │ System Activity    │                        │
│  │ Processes      │ │                    │                        │
│  └────────────────┘ └────────────────────┘                        │
└────────────────────────┬──────────────────────────────────────────┘
                         │ REST + WebSocket
┌────────────────────────▼──────────────────────────────────────────┐
│                    FASTAPI BACKEND (uvicorn :8000)                  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  SystemMonitor (3s loop) — snapshot, scan, poll, publish │    │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────┐ ┌─────────────────┐ ┌──────────────┐   │
│  │  ThreatEngine        │ │  AI Modules     │ │  Database    │   │
│  │  (detection.py)      │ │  (gemini, voice,│ │  (SQLite)    │   │
│  │   + 9 Engines        │ │   mitre, etc.) │ │  + Log Buffer│   │
│  └──────────────────────┘ └─────────────────┘ └──────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Detection Engines — Detailed Capabilities

### Engine 1: System Activity Monitoring Engine
**File:** `backend/engines/system_activity.py`

- Tracks process creation and termination in real-time
- Groups processes by **name** (not individual PIDs) to eliminate sub-process noise
- "App opened" fires only when a process name first appears
- "App closed" fires only when all instances of a process name disappear
- Maintains a rolling buffer of 200 recent activity events

### Engine 2: Resource Usage Analyzer
**File:** `backend/engines/resource_analyzer.py`

- Collects CPU, RAM, disk I/O, and network connections per process
- Aggregates same-named processes (e.g., multiple chrome.exe instances)
- Ranks processes by resource score (CPU + memory + recency boost)
- Tracks disk read/write in MB per process
- Flags processes with CPU > 90% or RAM > 80% as "High" status

### Engine 3: AI Activity Attribution Engine
**File:** `backend/engines/ai_attribution.py`

- Detects AI coding tool processes via process chain analysis (up to 5 levels deep)
- **Supported tools:** Cursor AI, Claude Code, GitHub Copilot, VS Code, Cline, Roo Code, Windsurf, Aider
- Detects dangerous commands: `git reset --hard`, `rm -rf`, `del /s`, `diskpart`, `format`, `shutdown`, `bcdedit`, `cipher /w`
- Confidence scoring: 70% base + bonuses for shell (+10), dangerous commands (+12), parent chain (+5)

### Engine 4: Code Protection Engine
**File:** `backend/engines/code_protection.py`

- Monitors file system events via watchdog (Desktop, Documents, Downloads)
- 12-second sliding window for burst detection
- **Thresholds:** 20+ deletions → mass deletion, 30+ renames → mass rename, 50+ modifications → bulk modification
- 45-second cooldown between alerts

### Engine 5: USB Security Engine
**File:** `backend/engines/usb_security.py`

- Auto-detects USB storage via WMI + Windows API + psutil
- **Deep scan:** autorun files, suspicious executables, double-extension tricks, script files, hidden files
- **Virus scan:** SHA-256 hash matching against known malware, PE header analysis (packer detection: UPX, Themida, VMP)
- **Heuristic scan:** malicious pattern matching in script/text files (Mimikatz, encoded PowerShell, WScript, etc.)
- Scans up to 1000 files per device, 50MB per-file limit

### Engine 6: Threat Detection Engine
**File:** `backend/detection.py`

- Encoded PowerShell detection (`-enc`, `-encodedcommand`, `frombase64`, `-windowstyle hidden`)
- High CPU (>90%) and high memory (>80%) alerts
- Abnormal resource usage (CPU > 88% or memory > 55%)
- AI-origin shell process detection (shell spawned by AI tool)
- **Anomaly Detection:** Isolation Forest ML model trained on 120 snapshots, refits every 30s, contamination 8%
- Fallback threshold: CPU > 97% or memory > 98%

### Engine 7: Log Correlation Engine
**File:** `backend/detection.py` (correlate method)

- Correlates events across multiple detection categories
- Triggers "Correlated Intrusion Pattern" when 3+ distinct categories appear within 5 minutes
- 3-minute cooldown between correlation alerts

### Engine 8: Risk Scoring Engine
**File:** `backend/engines/risk.py`

- **Event-based scoring (0-100):** ransomware=80, threat_detected=75, intrusion=70, system_error=55, registry=50, etc.
- **Time-decay algorithm:** 20-minute window, older events decay to 25% minimum weight
- **Critical events:** minimum score 85, multiplied by 1.1
- **Deduplication** by (event_type, source, record, pid, title)
- **Risk bands:** 0-19 Safe, 20-49 Warning, 50-79 High Risk, 80-100 Critical
- **Remediation engine:** per-threat-type immediate/investigate/prevent steps with context-aware dynamic steps
- **Emergency escalation** when score >= 70

### Engine 9: AI Analysis Module (Local Algorithm)
**File:** `backend/engines/ai_analysis.py`

- 100% local analysis — no external API needed
- 15-second cache TTL, re-evaluates on score change >= 10 points
- **Analysis:** temporal burst detection, critical/high categorization, USB analysis, AI tool attribution, file analysis, threat tracking, resource anomalies
- **Interactive Q&A:** routes questions to specialized analyzers (process, risk, USB, AI attribution, file, logs, overview)
- **Dynamic recommendations** based on current findings

### Engine 10: Local Analytics Engine
**File:** `backend/engines/local_analytics.py`

- Log aggregation (grouping by category, severity, source, event type, time window)
- **Attack chain detection:** 10 predefined attack progression patterns
  - Credential Attack → Execution/Persistence/Privilege Escalation
  - USB → Malware Execution/Persistence
  - Execution → Ransomware/Data Destruction
  - Persistence → Execution → Exfiltration
  - AI-Assisted Attack Chain, Ransomware → File Encryption
- Per-incident risk scoring with category breakdown
- Statistical anomaly detection (event bursts, severity spikes, CPU/memory anomalies, event concentration)
- Incident timeline construction with attack phases (MITRE-aligned)
- Markdown report generation with executive summary, timeline, risk assessment, attack chains, anomalies, top processes, event distribution, recommended actions

### Engine 11: Performance Optimizer
**File:** `backend/engines/performance_optimizer.py`

- Scans all running processes, classifies as optimizable or protected
- **Protected:** 60+ Windows-critical processes (system, lsass, svchost, Defender, etc.)
- **Optimizable categories:** browser, messaging, media, cloud-sync, updater, office, dev-tools, remote, misc
- Safe-to-stop filtering (CPU < 1.5% and RAM < 0.5% skipped)
- Per-process kill with PID-reuse protection and graceful → force-kill fallback
- Batch kill all safe-rated processes
- Risk reduction estimation

### Engine 12: Gemini Threat Intelligence
**File:** `backend/ai/gemini_analyzer.py`

- Google Gemini API integration with graceful fallback to local algorithm
- **Severity gating:** only calls Gemini for medium+ severity events
- **Rate limiting:** cooldown between non-critical calls
- **Response cache:** persistent cache with TTL for similar incidents
- **Local analytics context:** sends pre-processed reports instead of raw logs (cost optimization)
- **Features:** threat analysis, alert explanation, incident reports, conversational response (ChatGPT Voice style), deep investigation, guided remediation (step-by-step), resolution verification
- **Retry:** 4 attempts with backoff (0s, 3s, 5s, 10s)

### Engine 13: Multilingual Voice Assistant
**File:** `backend/ai/sarvam_voice.py`

- 12 languages: English, Hindi, Marathi, Gujarati, Telugu, Tamil, Kannada, Malayalam, Bengali, Punjabi, Odia, Assamese
- **3-tier TTS fallback:** Primary (Google Cloud TTS) → Sarvam AI → Edge TTS → Browser TTS
- Hindi + English routed through Sarvam AI (higher quality)
- Pre-built alert translations for all languages
- Voice report pipeline: local analytics → translation → TTS synthesis
- Conversational AI voice (ChatGPT Voice / Gemini Live style)
- Deep investigation mode with timeline and findings
- Guided step-by-step remediation with human-in-the-loop
- Resolution verification

### Engine 14: MITRE ATT&CK Mapper
**File:** `backend/ai/mitre_mapper.py`

- Rule-based mapping of 20+ event types to MITRE ATT&CK techniques
- **Mapped techniques:** T1059.001 (PowerShell), T1547.001 (Registry Run Keys), T1110.001 (Brute Force), T1486 (Data Encrypted), T1091 (USB), T1027 (Obfuscation), etc.
- Active tactics summary with technique references
- MITRE ATT&CK v14 framework

---

## 5. Telemetry Collectors

### Windows Event Log Collectors (`backend/telemetry.py`)

| Log Source | Collector | Events |
|------------|-----------|--------|
| Security | SecurityEventCollector | 4625 (failed login), 4740 (lockout), brute force (5+ in 60s) |
| System | ApplicationLogCollector | Service failures (7000-7036), errors, warnings |
| Application | ApplicationLogCollector | Crashes (1000-1008), errors, threat keywords |
| Setup | ApplicationLogCollector | OS installation and update events |
| Windows PowerShell | ApplicationLogCollector | PowerShell execution events |

- Bootstrap: loads 150 recent records on startup (12-hour window)
- Buffer: 300 entries in memory (ring buffer)
- Alert throttle: 180s cooldown per (log_name:event_id:source)

### USB Device Monitor
- Detects USB via WMI (Win32_DiskDrive), Windows API (GetDriveTypeW), psutil
- Tracks insertion/removal, auto-scans on insertion

### Startup Registry Monitor
- Monitors `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Detects new or modified startup entries

### File Activity Watcher
- Monitors Desktop, Documents, Downloads via watchdog
- Ransomware thresholds: 100+ writes, 25+ renames, 15+ extension changes in 10 seconds

---

## 6. API Endpoints

### Core REST
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/overview` | Dashboard overview (score, severity, categories, telemetry) |
| GET | `/api/alerts` | Visible alerts (deduped, noise-filtered) |
| GET | `/api/snapshots` | System resource snapshots history |
| GET | `/api/processes` | Active processes ranked by resource usage |
| GET | `/api/activity` | Live activity feed (process + USB) |
| GET | `/api/usb/activity` | USB-specific activity history |
| GET | `/api/usb/status` | Connected USB devices with scan results |
| GET | `/api/modules` | Engine module inventory with status |
| GET | `/api/ai-analysis` | Local AI analysis report |
| POST | `/api/ai-question` | Ask questions about system state |
| GET | `/api/telemetry` | Collector health status |
| GET | `/api/logs/recent` | Recent Windows event log entries |
| POST | `/api/reset` | Clear all events |
| GET | `/api/report.csv` | Download CSV incident report |
| GET | `/api/analytics/report` | Local analytics report (no Gemini) |

### AI / Gemini
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/gemini/status` | Gemini API availability |
| GET | `/api/gemini/analyze` | Gemini-powered threat analysis |
| POST | `/api/gemini/explain` | Explain why an alert was generated |
| GET | `/api/gemini/incident-report` | AI-assisted incident report |
| GET | `/api/mitre-mapping` | MITRE ATT&CK mapping |

### Voice / TTS
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/voice/speak` | Text-to-speech synthesis |
| POST | `/api/voice/alert` | Convert alert to voice notification |
| POST | `/api/voice/analysis` | Convert analysis to voice |
| POST | `/api/voice/report` | Multilingual voice report pipeline |
| POST | `/api/voice/converse` | Conversational AI voice |
| POST | `/api/voice/investigate` | Deep investigation with voice |
| POST | `/api/voice/guide` | Guided step-by-step remediation |
| POST | `/api/voice/verify` | Verify threat resolution |
| GET | `/api/voice/languages` | Supported voice languages |

### Performance Optimizer
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/optimizer/scan` | Scan optimizable processes |
| POST | `/api/optimizer/kill` | Kill a single process by PID |
| POST | `/api/optimizer/kill-all` | Kill all safe-rated processes |

### WebSocket
| Endpoint | Messages |
|----------|----------|
| `/ws` | `connected`, `alert`, `snapshot`, `processes`, `activity`, `logs`, `reset` |

---

## 7. Frontend Dashboard Sections

| Section | Component | Description |
|---------|-----------|-------------|
| Header | `Header.jsx` | App title, monitoring status, local time |
| Security Index | `SecurityIndex.jsx` | Risk score gauge (0-100), severity badge |
| Endpoint Status | `EndpointStatus.jsx` | CPU, RAM, disk, network, temperatures |
| Stat Cards | `StatCards.jsx` | Alert counts, AI events, USB events summary |
| Live Threat Feed | `LiveThreatFeed.jsx` | Real-time alerts + activity feed |
| USB Security | `USBSecurity.jsx` | Connected USB devices with scan status |
| AI Analysis | `AIAnalysis.jsx` | Local algorithm report + interactive Q&A |
| Threat Summary | `ThreatSummary.jsx` | Categorized alert counts + action items |
| Alert Timeline | `AlertTimeline.jsx` | Bar chart of alert frequency over time |
| AI Threat Summary | `AIThreatSummary.jsx` | Gemini analysis + MITRE ATT&CK mapping |
| Voice Alert Player | `VoiceAlertPlayer.jsx` | Multilingual voice alert playback |
| Module Matrix | `ModuleMatrix.jsx` | 13+ engine status cards |
| Log Detection | `LogDetection.jsx` | Real-time Event Log stream table |
| Collector Health | `CollectorHealth.jsx` | Telemetry source status indicators |
| Active Processes | `ActiveProcesses.jsx` | Ranked process list with CPU, RAM, disk I/O |
| System Activity | `SystemActivity.jsx` | App open/close history |
| Explain Alert Modal | `ExplainAlertModal.jsx` | Gemini-powered alert explanation |
| Toast | `Toast.jsx` | In-app notification popups |

---

## 8. Data Flow

### Real-Time Loop (every ~3 seconds)
1. **Snapshot Collection** → CPU, memory, disk, network stats → stored in SQLite
2. **Process Scan** → detect new/removed apps, inspect for threats → record events
3. **Resource Collection** → aggregate process resources → broadcast to frontend
4. **Telemetry Poll** → all collectors (Security/Application/System logs, USB, registry, file system)
5. **Log Push** → new entries via WebSocket

### Alert Processing Pipeline
1. Engine detects event → `create_event()` (score + severity)
2. Time-based dedup (120s cooldown per event_type + title + process)
3. Stored in SQLite database
4. Broadcast via WebSocket to frontend
5. USB events → also published to USB activity feed
6. High/critical → desktop WPF popup notification + system sound
7. `correlate()` — cross-category intrusion pattern check
8. `LocalAnalyticsEngine.correlate_events()` — attack chain detection

---

## 9. Deduplication Systems

| Layer | Mechanism | Scope |
|-------|-----------|-------|
| Process Activity | Name-based grouping | Prevents sub-process flood |
| Event Recording | Time-based (120s) | Same event_type + title + process |
| Alert Display | Query-level dedup | Same event_type + title + summary[:120] |
| CSV Export | Query-level dedup | Clean report |
| Log Stream | Record + log_name dedup | Frontend merge |
| Alert Throttle | 180s per log source:key | Log-based alert flooding |

---

## 10. Scoring & Severity Matrix

| Event Type | Score | Default Severity |
|------------|-------|-----------------|
| ransomware_activity | 80 | Critical |
| threat_detected | 75 | High |
| intrusion_correlation | 70 | High |
| system_error | 55 | High |
| usb_threat_detected | 55 | High |
| malware_signature | 50 | Medium |
| registry_persistence | 50 | Medium |
| application_crash | 45 | Medium |
| mass_file_deletion | 45 | Medium |
| suspicious_chain | 45 | Medium |
| powershell_encoded | 40 | Medium |
| dangerous_command | 40 | Medium |
| service_failure | 40 | Medium |
| ai_assisted_command | 35 | Medium |
| account_lockout | 35 | Medium |
| suspicious_process | 30 | Medium |
| usb_scan_suspicious | 30 | Medium |
| anomaly | 25 | Medium |
| usb_device | 20 | Medium |
| failed_login | 10 | Low |
| high_cpu/memory | 5 | Low |

---

## 11. How to Run

### Prerequisites
- Windows 10/11
- Python 3.10+
- Node.js 18+

### Desktop App (Recommended)
```bash
run_trinetra_desktop.bat
```
Or manually:
```bash
cd frontend && npm install && npm run electron
```

### Browser Mode (Quick Testing)
```bash
run_trinetra.bat
# or
pip install -r requirements.txt
python -m backend
# Open http://127.0.0.1:8000
```

### Development
```bash
# Backend
python -m backend

# Frontend hot-reload
cd frontend && npm install && npm run dev

# Electron dev
cd frontend && npm run electron
```

---

## 12. Key Features Summary

1. **14 Detection & Analysis Engines** running concurrently
2. **Desktop-native** — Electron app with auto-backend management
3. **Real-time WebSocket updates** every ~3 seconds
4. **5 Windows Event Log sources** (Security, System, Application, Setup, PowerShell)
5. **USB Security Scanning** — deep virus scan + heuristic analysis
6. **AI Coding Tool Detection** — 8 tools supported
7. **Code Protection** — mass deletion/rename/modification detection
8. **ML Anomaly Detection** — Isolation Forest
9. **Cross-Category Correlation** — intrusion pattern detection
10. **Risk Scoring** with time-decay + remediation engine
11. **Local AI Analysis** — algorithm-based Q&A system
12. **Local Analytics Engine** — attack chains, incident timeline, reports
13. **Gemini Threat Intelligence** — with cost optimization features
14. **Multilingual Voice Assistant** — 12 languages, 3-tier TTS fallback
15. **MITRE ATT&CK Mapping** — 20+ techniques mapped
16. **Performance Optimizer** — safe process termination
17. **WPF Desktop Notifications** — severity-colored popups
18. **CSV Incident Report** export
19. **Dark theme desktop dashboard** with responsive grid layout
