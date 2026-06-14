# Quick Start Guide — Trinetra Sentinel Desktop EDR

## What You Get

A **desktop-native EDR application** that monitors your Windows endpoint in real-time,
detects threats across 13+ engines, and provides a SOC-style dashboard with AI-powered
analysis and multilingual voice assistant.

---

## Getting Started

### Step 1: Launch the Desktop App

Double-click:

```text
run_trinetra_desktop.bat
```

Or manually:

```powershell
cd frontend && npm install && npm run electron
```

The Electron app will:
1. Create a Python virtual environment (if missing)
2. Install Python dependencies
3. Start the FastAPI backend on `http://127.0.0.1:8000`
4. Build the React dashboard
5. Open the Trinetra Sentinel desktop window

### Step 2: Explore the Dashboard

| Section | What to Look For |
|---------|-----------------|
| **Security Index** | Overall risk score (0-100) with severity badge |
| **Endpoint Status** | Live CPU, RAM, disk, network, temperatures |
| **Live Threat Feed** | Real-time alerts color-coded by severity |
| **USB Security** | Connected USB devices with scan results |
| **AI Analysis** | Local threat summary with findings and recommendations |
| **Voice Assistant** | Multilingual voice alerts and conversational AI |
| **Threat Summary** | Categorized alert counts and action items |
| **Alert Timeline** | Bar chart of alert frequency over time |
| **Module Matrix** | Status of all 13+ detection engines |
| **Log Detection** | Real-time Windows Event Log stream |
| **Collector Health** | Status of all telemetry collectors |
| **Active Processes** | Ranked process list with CPU/RAM/disk I/O |

---

## Alert Severity Guide

| Severity | Color | Score Range | Example |
|----------|-------|-------------|---------|
| **Critical** | Red | 80-100 | Ransomware activity, correlated intrusion |
| **High** | Orange | 50-79 | Threat detected, USB threat, malware signature |
| **Medium** | Yellow | 20-49 | Suspicious process, encoded PowerShell, crash |
| **Low** | Blue | 0-19 | Failed login, high CPU/memory usage |

### Notifications

- **Critical/High** → WPF desktop popup (bottom-right) + system alert sound
- **Medium** → WPF popup only (no sound)
- All events appear in the Live Threat Feed and `notifications.log`

---

## AI Features (Optional — requires API keys)

Add to `.env` file in the project root:

```env
GEMINI_API_KEY=your_google_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
GOOGLE_APPLICATION_CREDENTIALS=path/to/gcp-service-account.json
SARVAM_API_KEY=your_sarvam_ai_api_key
```

Without these keys, all AI features fall back to local algorithms.

---

## Troubleshooting

### Backend won't start?
- Ensure Python 3.10+ is installed and in PATH
- Run `pip install -r requirements.txt` manually
- Check `trinetra.log` for error details

### Electron window is blank?
- Ensure the backend is running: check `http://127.0.0.1:8000` in a browser
- Run `cd frontend && npm run build` to rebuild the dashboard

### Collector shows "Limited"?
- Run as Administrator for full Windows Event Log access
- Some telemetry sources (Security Log, Registry) require elevated privileges

### Too many alerts?
- The system deduplicates and applies cooldowns automatically
- Low-severity events (score < 20) are hidden from the main feed

---

## Quick Commands

```powershell
# Desktop app
run_trinetra_desktop.bat

# Browser mode (no Electron)
run_trinetra.bat
# or
python -m backend                       # starts server
# then open http://127.0.0.1:8000

# Monitor notifications log
Get-Content -Path notifications.log -Tail 20 -Wait

# Export incident report
# Dashboard → click Export or GET /api/report.csv
```
