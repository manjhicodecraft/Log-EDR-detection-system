import asyncio
import csv
import io
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .database import Database
from .detection import ThreatEngine, severity_for, compute_risk_score
from .engines.risk import build_remediations
from .engines.ai_analysis import AIAnalysisModule
from .engines.usb_security import USBSecurityEngine
from .monitor import SystemMonitor
from .telemetry import USBCollector
from .ai.gemini_analyzer import GeminiThreatAnalyzer
from .ai.sarvam_voice import SarvamVoiceModule
from .ai.mitre_mapper import build_mitre_summary
from .engines.performance_optimizer import PerformanceOptimizer


ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "frontend" / "dist"
db = Database()
engine = ThreatEngine()
ai_analysis = AIAnalysisModule()
usb_status_scanner = USBSecurityEngine()
gemini_analyzer = GeminiThreatAnalyzer()
voice_module = SarvamVoiceModule()
optimizer = PerformanceOptimizer()
clients: set[WebSocket] = set()


async def broadcast(message: dict):
    stale = []
    for client in clients:
        try:
            await client.send_json(message)
        except Exception:
            stale.append(client)
    for client in stale:
        clients.discard(client)


monitor = SystemMonitor(db, engine, broadcast)


NOISE_EVENT_TYPES = {"system_warning", "usb_removed", "usb_scan_clean", "process_started", "process_stopped", "normal_activity"}


def visible_alerts(events: list[dict]) -> list[dict]:
    rows = []
    seen = set()
    for event in events:
        if event.get("event_type") in NOISE_EVENT_TYPES:
            continue
        if event.get("title") == "USB storage device detected":
            continue
        if int(event.get("score", 0)) < 20 and event.get("severity") not in {"high", "critical"}:
            continue
        # Dedup: same event_type + title + summary = skip within the list
        dedup_key = (event.get("event_type"), event.get("title"), event.get("summary", "")[:120])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        rows.append(event)
    return rows


@asynccontextmanager
async def lifespan(app: FastAPI):
    monitor.loop = asyncio.get_running_loop()
    task = asyncio.create_task(monitor.run())
    yield
    monitor.stop()
    task.cancel()


app = FastAPI(title="Trinetra Sentinel", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def overview() -> dict:
    events = visible_alerts(db.list_events(200))
    score = compute_risk_score(events)
    severity = severity_for(score)
    categories = {}
    for event in events:
        categories[event["category"]] = categories.get(event["category"], 0) + 1
    ai_events = [event for event in events if event.get("metadata", {}).get("ai_attribution")]
    usb_events = [
        event
        for event in events
        if event.get("source") in {"usb-monitor", "usb-security-engine"} or event.get("category") == "usb-security"
    ]
    events_for_remediation = visible_alerts(db.list_events(200))
    remediations = build_remediations(events_for_remediation, score)
    return {
        "score": score,
        "severity": severity,
        "risk_band": _risk_band(score),
        "alerts": len(events),
        "critical": sum(event["severity"] == "critical" for event in events),
        "snapshot": monitor.last_snapshot,
        "categories": categories,
        "telemetry": monitor.telemetry.status,
        "ai_attributed": len(ai_events),
        "usb_events": len(usb_events),
        "remediations": remediations,
        "previews": {
            "alerts": [_preview_event(event) for event in events[:4]],
            "ai_attributed": [_preview_event(event) for event in ai_events[:4]],
            "usb_events": [_preview_event(event) for event in usb_events[:4]],
        },
    }


def _risk_band(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High Risk"
    if score >= 20:
        return "Warning"
    return "Safe"


def _preview_event(event: dict) -> dict:
    metadata = event.get("metadata") or {}
    process_name = metadata.get("name")
    return {
        "title": process_name or event.get("title", "Activity"),
        "detail": event.get("summary", "")[:90],
        "severity": event.get("severity", "low"),
        "time": event.get("timestamp"),
    }


def module_inventory() -> list[dict]:
    telemetry = monitor.telemetry.status
    return [
        {"name": "System Activity Monitoring Engine", "status": "active", "detail": "Process creation, termination, app open/close, services, and endpoint snapshots."},
        {"name": "Resource Usage Analyzer", "status": "active", "detail": "CPU, RAM, disk read/write, process status, and active-process ranking."},
        {"name": "AI Activity Attribution Engine", "status": "active", "detail": "Detects Cursor, Claude Code, Copilot, Cline, Roo Code, Windsurf, and Aider process chains."},
        {"name": "Code Protection Engine", "status": telemetry.get("file_activity", {}).get("state", "pending"), "detail": "Detects mass deletion, renaming, and bulk modification; recommends snapshot or git backup commit."},
        {"name": "USB Security Engine", "status": telemetry.get("usb_devices", {}).get("state", "pending"), "detail": "Auto-detects USB storage and scans executables, scripts, autorun files, and hidden files."},
        {"name": "Threat Detection Engine", "status": "active", "detail": "Rule-based detections for suspicious process chains, resource abuse, logs, registry persistence, and malware-like behavior."},
        {"name": "Log Correlation Engine", "status": "active", "detail": "Connects USB, process, network/log, authentication, persistence, and file events into incident chains."},
        {"name": "Risk Scoring Engine", "status": "active", "detail": "Maps events to 0-100 risk: Safe, Warning, High Risk, and Critical."},
        {
            "name": "AI Analysis Module",
            "status": "active",
            "detail": "Local algorithm-based analysis engine — no external API dependency.",
        },
        {
            "name": "Gemini Threat Intelligence",
            "status": "active" if gemini_analyzer.available else "limited",
            "detail": "Gemini-powered threat summarization, MITRE ATT&CK mapping, explainable alerts, and incident reports.",
        },
        {
            "name": "Sarvam AI Voice Assistant",
            "status": "active" if voice_module.available else "limited",
            "detail": "Multilingual voice notifications (English, Hindi, Telugu) via Sarvam AI TTS with browser fallback.",
        },
        {
            "name": "Performance Optimizer",
            "status": "active",
            "detail": "Scans processes, identifies resource-heavy tasks safe to stop, protects Windows-critical processes.",
        },
    ]


@app.get("/api/overview")
def get_overview():
    return overview()


@app.get("/api/alerts")
def get_alerts(limit: int = 40):
    return visible_alerts(db.list_events(200))[: min(limit, 200)]


@app.get("/api/snapshots")
def get_snapshots(limit: int = 24):
    return db.latest_snapshots(min(limit, 120))


@app.get("/api/processes")
def get_processes():
    return monitor.active_processes()


@app.get("/api/activity")
def get_activity(limit: int = 120):
    limit = min(limit, 200)
    activity = [*monitor.recent_activity(200), *monitor.recent_usb_activity(120)]
    activity.sort(key=lambda item: item["timestamp"], reverse=True)
    return activity[:limit]


@app.get("/api/usb/activity")
def get_usb_activity(limit: int = 30):
    events = db.list_events(160)
    rows = [*monitor.recent_usb_activity(80)]
    seen = {(item.get("timestamp"), item.get("event_type"), item.get("name")) for item in rows}
    for event in events:
        if event.get("source") not in {"usb-monitor", "usb-security-engine"} and event.get("category") != "usb-security":
            continue
        metadata = event.get("metadata", {})
        device = metadata.get("device") or metadata
        scan = metadata.get("scan") or {}
        findings = scan.get("findings") or []
        row = {
            "timestamp": event["timestamp"],
            "event_type": event.get("event_type", "usb_activity"),
            "title": event["title"],
            "summary": event["summary"],
            "pid": "USB",
            "name": device.get("name") or device.get("path") or device.get("mountpoint") or "USB device",
            "username": f"{len(findings)} finding(s)" if scan else "scan pending",
            "source": event.get("source"),
            "severity": event.get("severity", "low"),
            "score": event.get("score", 0),
        }
        key = (row["timestamp"], row["event_type"], row["name"])
        if key not in seen:
            seen.add(key)
            rows.append(row)
    rows.sort(key=lambda item: item["timestamp"], reverse=True)
    return rows[: min(limit, 80)]


@app.get("/api/usb/status")
def get_usb_status():
    devices = []
    inventory_error = None
    try:
        inventory = USBCollector._inventory()
    except Exception as exc:
        inventory = {}
        inventory_error = f"{type(exc).__name__}: {exc}"

    for key, device in inventory.items():
        scan = usb_status_scanner.scan_device(device, max_files=600)
        findings = scan.get("findings", [])
        threat_level = scan.get("threat_level", "unknown")
        if threat_level == "clean":
            status = "Safe to use"
        elif threat_level == "critical":
            status = "Virus/malware detected!"
        elif threat_level == "high":
            status = "Threat-like files found"
        elif threat_level in {"medium", "low"}:
            status = "Review before use"
        elif not scan.get("scanned"):
            status = "Connected, scan limited"
        else:
            status = "Connected"
        virus_scan = scan.get("virus_scan", {})
        devices.append(
            {
                "id": key,
                "name": device.get("name") or key,
                "mountpoint": device.get("mountpoint") or device.get("path") or "",
                "volume_name": device.get("volume_name") or "",
                "filesystem": device.get("filesystem") or "",
                "status": status,
                "threat_level": threat_level,
                "findings": len(findings),
                "files_scanned": scan.get("files_scanned", 0),
                "scanned": bool(scan.get("scanned")),
                "scan_reason": scan.get("reason", ""),
                "risky_files": findings[:8],
                "virus_scan": {
                    "status": virus_scan.get("status", "pending"),
                    "files_checked": virus_scan.get("checked", 0),
                    "virus_hits": virus_scan.get("hits", 0),
                    "heuristic_hits": virus_scan.get("heuristic_hits", 0),
                    "details": virus_scan.get("details", []),
                },
            }
        )

    return {
        "connected": len(devices),
        "devices": devices,
        "error": inventory_error,
    }


@app.get("/api/modules")
def get_modules():
    return module_inventory()


@app.get("/api/ai-analysis")
def get_ai_analysis(force: bool = False):
    events = db.list_events(200)
    score = compute_risk_score(events)
    return ai_analysis.summarize(
        events,
        score,
        processes=monitor.active_processes(),
        snapshot=monitor.last_snapshot,
        logs=monitor.telemetry.log_stream.list(50),
        force=force,
    )


@app.post("/api/ai-question")
def ask_ai_question(payload: dict = Body(...)):
    events = db.list_events(200)
    score = compute_risk_score(events)
    return ai_analysis.answer_question(
        str(payload.get("question", "")),
        events,
        score,
        processes=monitor.active_processes(),
        snapshot=monitor.last_snapshot,
        logs=monitor.telemetry.log_stream.list(50),
    )


@app.get("/api/telemetry")
def get_telemetry():
    return monitor.telemetry.status


@app.get("/api/logs/recent")
def get_recent_logs(limit: int = 80):
    stream = monitor.telemetry.log_stream
    return {
        "entries": stream.list(min(limit, 150)),
        "stats": stream.stats(),
    }


@app.post("/api/reset")
async def reset():
    db.clear_events()
    await broadcast({"kind": "reset", "data": overview()})
    return {"ok": True}


@app.get("/api/report.csv")
def report():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "severity", "category", "title", "summary", "score", "source"])
    seen = set()
    for event in db.list_events(1000):
        dedup_key = (event.get("event_type"), event.get("title"), event.get("summary", "")[:120])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        writer.writerow([event[key] for key in ("timestamp", "severity", "category", "title", "summary", "score", "source")])
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trinetra-incident-report.csv"},
    )


# ──────────────────────────────────────────────────────────────
# Gemini + Sarvam AI endpoints (additive — no existing code modified)
# ──────────────────────────────────────────────────────────────


@app.get("/api/gemini/status")
def get_gemini_status():
    """Check if Gemini API is configured and available."""
    return {
        "available": gemini_analyzer.available,
        "model": gemini_analyzer._model_name if gemini_analyzer._available else None,
        "provider": "gemini" if gemini_analyzer._available else "local-fallback",
    }


@app.get("/api/gemini/analyze")
def get_gemini_analysis():
    """Gemini-powered threat analysis with MITRE ATT&CK mapping."""
    events = db.list_events(200)
    score = compute_risk_score(events)
    return gemini_analyzer.analyze_threat(events, score)


@app.post("/api/gemini/explain")
def explain_alert(payload: dict = Body(...)):
    """Explain why a specific alert was generated."""
    alert_data = payload.get("alert", {})
    all_events = db.list_events(200)
    return gemini_analyzer.explain_alert(alert_data, all_events)


@app.get("/api/gemini/incident-report")
def get_incident_report():
    """Generate AI-assisted incident report."""
    events = db.list_events(200)
    score = compute_risk_score(events)
    return gemini_analyzer.generate_incident_report(events, score)


@app.get("/api/mitre-mapping")
def get_mitre_mapping():
    """Get MITRE ATT&CK mapping for current events."""
    events = db.list_events(200)
    return build_mitre_summary(events)


@app.post("/api/voice/speak")
def speak_text(payload: dict = Body(...)):
    """Convert text to speech via Sarvam AI."""
    text = payload.get("text", "")
    language = payload.get("language", "en")
    if not text:
        return {"error": "No text provided", "provider": "none"}
    return voice_module.synthesize_speech(text, language)


@app.post("/api/voice/alert")
def speak_alert(payload: dict = Body(...)):
    """Convert an alert to multilingual voice notification."""
    alert_data = payload.get("alert", {})
    language = payload.get("language", "en")
    return voice_module.speak_alert(alert_data, language)


@app.post("/api/voice/analysis")
def speak_analysis(payload: dict = Body(...)):
    """Convert Gemini analysis to voice notification."""
    text = payload.get("text", "")
    language = payload.get("language", "en")
    if not text:
        return {"error": "No text provided", "provider": "none"}
    return voice_module.speak_analysis(text, language)


@app.get("/api/voice/languages")
def get_voice_languages():
    """Get supported voice languages."""
    return {
        "languages": voice_module.get_supported_languages(),
        "available": voice_module.available,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Performance Optimizer endpoints (additive — no existing code modified)
# ──────────────────────────────────────────────────────────────────────────────


@app.get("/api/optimizer/scan")
def optimizer_scan():
    """Scan running processes and return optimizable vs protected list."""
    return optimizer.scan_optimizable()


@app.post("/api/optimizer/kill")
def optimizer_kill(payload: dict = Body(...)):
    """Safely kill a single process by PID with critical-process safety checks."""
    pid = payload.get("pid")
    name = payload.get("name", "")
    if not pid or not isinstance(pid, int):
        return {"success": False, "error": "Invalid or missing PID"}

    result = optimizer.kill_process(pid, name)

    # Log the kill event to database
    if result["success"]:
        event = engine.create_event(
            "process_terminated",
            f"Process stopped: {result['name']} (PID {pid})",
            f"User terminated {result['name']} via Performance Optimizer.",
            "system",
            source="performance-optimizer",
            metadata={"pid": pid, "name": result["name"]},
        )
        event["score"], event["severity"] = 0, "low"
        db.add_event(event)

    return result


@app.post("/api/optimizer/kill-all")
def optimizer_kill_all():
    """Kill all 'safe' rated processes in one batch."""
    result = optimizer.kill_all_safe()

    # Log each successful kill
    for r in result.get("results", []):
        if r["success"]:
            event = engine.create_event(
                "process_terminated",
                f"Process stopped: {r['name']} (PID {r['pid']})",
                f"Batch-terminated {r['name']} via Performance Optimizer.",
                "system",
                source="performance-optimizer",
                metadata={"pid": r["pid"], "name": r["name"], "batch": True},
            )
            event["score"], event["severity"] = 0, "low"
            db.add_event(event)

    return result


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        await websocket.send_json({"kind": "connected", "data": overview()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)


if STATIC.exists():
    assets_dir = STATIC / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    index = STATIC / "index.html"
    if not index.exists():
        return HTMLResponse(
            "<h1>Trinetra Sentinel</h1>"
            "<p>Frontend not built. Run <code>cd frontend && npm install && npm run build</code></p>",
            status_code=503,
        )
    return index.read_text(encoding="utf-8")
