# Trinetra Sentinel

Offline-first local EDR prototype. It collects real endpoint telemetry, stores alerts
in SQLite, scores suspicious behavior, and streams live detections to a SOC-style
dashboard.

## Run

On Windows, double-click:

```text
run_trinetra.bat
```

The launcher creates a local Python environment, installs missing packages on the
first run, starts the server, and opens the dashboard automatically.

Manual setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m backend
```

Open `http://127.0.0.1:8000`.

Desktop app:

```text
run_trinetra_desktop.bat
```

Or manually:

```powershell
cd frontend
npm install
npm run electron
```

The Electron app builds the React dashboard, starts the FastAPI backend if it is
not already running, then opens Trinetra Sentinel in a desktop window.

The dashboard is a **React + Vite** app in `frontend/`. `run_trinetra.bat` builds it
automatically when Node.js is installed.

Frontend development (hot reload with API proxy):

```powershell
cd frontend
npm install
npm run dev
```

In another terminal, start the backend with `python -m backend`, then open
`http://127.0.0.1:5173`.

Production build:

```powershell
cd frontend
npm run build
```

## Included

- React + Vite SOC dashboard
- FastAPI backend with WebSocket updates
- SQLite event and system snapshot storage
- `psutil` local process and resource monitoring
- Windows Security Event Log monitoring for failed logins and account lockouts
- Live USB storage insertion and removal monitoring
- Startup registry monitoring for persistence behavior
- Event-driven file monitoring for ransomware-like write and rename bursts
- Correlation alerts when multiple suspicious activity categories occur together
- Offline Isolation Forest anomaly detector with threshold fallback
- Behavior-based rule engine and dynamic threat scoring
- CSV incident report export
- Responsive dashboard with live alert timeline and AI-style local summaries

## Notes

Windows Security Log visibility depends on the current user's Event Log permissions.
The dashboard Collector Health panel reports whether each real telemetry source is
active or limited. Set `TRINETRA_WATCH_PATHS` with semicolon-separated folders before
launching to override the default Desktop, Documents, and Downloads file watchers.
