import asyncio
import logging
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .database import Database
from .detection import ThreatEngine
from .engines.resource_analyzer import ResourceUsageAnalyzer
from .engines.system_activity import SystemActivityEngine
from .telemetry import TelemetryManager
from .notifications import notify

LOG_NOTIFY_TYPES = {
    "system_error",
    "application_crash",
    "service_failure",
    "threat_detected",
    "usb_scan_suspicious",
    "usb_threat_detected",
    "usb_device",
    "failed_login",
    "account_lockout",
    "intrusion_correlation",
    "mass_file_deletion",
    "mass_file_rename",
    "bulk_file_modification",
    "powershell_encoded",
    "dangerous_command",
    "ai_assisted_command",
    "ransomware_activity",
    "registry_persistence",
    "malware_signature",
    "suspicious_chain",
}

logger = logging.getLogger(__name__)


def should_notify(event: dict) -> bool:
    severity = event.get("severity", "low")
    if severity in ("critical", "high"):
        return True
    if severity == "medium" and event.get("event_type") in LOG_NOTIFY_TYPES:
        return True
    return False


# Processes that should never trigger resource-based alerts (always high on Windows)
SKIP_RESOURCE_NAMES = {
    "system idle process",
    "system",
    "registry",
    "memory compression",
    "idle",
}


class SystemMonitor:
    def __init__(self, database: Database, engine: ThreatEngine, publish):
        self.db = database
        self.engine = engine
        self.publish = publish
        self.running = False
        self.last_snapshot = {}
        self.last_disk_io = None
        self.last_net_io = None
        self.last_io_time = None
        self.seen_processes: set[int] = set()
        self.process_alerts: set[int] = set()
        # Time-based dedup: (event_type, title, process_name) -> last recorded time
        self._alert_dedup: dict[tuple, float] = {}
        self._alert_cooldown = 120.0  # seconds before same event type can fire again
        self.activity = SystemActivityEngine()
        self.usb_activity: list[dict] = []
        self.resources = ResourceUsageAnalyzer()
        self.telemetry = TelemetryManager(engine, self.emit_threadsafe)
        self.last_loop_error = 0.0
        self._last_log_seq = 0  # track which log entries have been pushed via WS

    async def run(self):
        self.running = True
        self.telemetry.start()
        await self._safe_thread(self.telemetry.poll, "telemetry bootstrap")
        while self.running:
            try:
                snapshot = await self._safe_thread(self.collect_snapshot, "snapshot collection")
                if snapshot:
                    self.last_snapshot = snapshot
                    self.db.add_snapshot(snapshot)
                    await self.publish({"kind": "snapshot", "data": snapshot})
                    anomaly = await self._safe_thread(lambda: self.engine.inspect_snapshot(snapshot), "snapshot anomaly detection")
                    if anomaly:
                        await self.record(anomaly)

                activity_events = await self._safe_thread(self.scan_processes, "process scan") or []
                if activity_events:
                    await self.publish({"kind": "activity", "data": activity_events})

                active_processes = await self._safe_thread(self.active_processes, "resource collection") or []
                if active_processes:
                    await self.publish({"kind": "processes", "data": active_processes})

                await self._safe_thread(self.telemetry.poll, "telemetry poll")

                # Push new log entries via WebSocket for real-time updates
                new_logs, self._last_log_seq = self.telemetry.log_stream.entries_since(self._last_log_seq, limit=60)
                if new_logs:
                    await self.publish({"kind": "logs", "data": new_logs, "stats": self.telemetry.log_stream.stats()})
            except Exception as exc:
                self._mark_loop_error("monitor loop", exc)
            await asyncio.sleep(3)

    async def _safe_thread(self, func, label: str):
        try:
            return await asyncio.to_thread(func)
        except Exception as exc:
            self._mark_loop_error(label, exc)
            return None

    def _mark_loop_error(self, label: str, exc: Exception):
        logger.exception("Monitor %s failed", label)
        detail = f"{label} recovered after {type(exc).__name__}: {exc}"
        self.telemetry.set_status("monitor_loop", "limited", detail[:240])
        now = time.monotonic()
        if now - self.last_loop_error < 120:
            return
        self.last_loop_error = now
        try:
            event = self.engine.create_event(
                "monitor_recovered",
                "Monitor recovered from collector error",
                detail[:220],
                "system",
                source="monitor-loop",
            )
            event["score"], event["severity"] = 15, "low"
            self.db.add_event(event)
            asyncio.run_coroutine_threadsafe(self.publish({"kind": "activity", "data": [event]}), self.loop)
        except Exception:
            logger.exception("Failed to publish monitor recovery event")

    def collect_snapshot(self) -> dict:
        try:
            connections = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, OSError):
            connections = 0
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()
        now = datetime.now(timezone.utc)
        elapsed = max((now - self.last_io_time).total_seconds(), 1) if self.last_io_time else 1
        disk_read_rate = 0.0
        disk_write_rate = 0.0
        upload_rate = 0.0
        download_rate = 0.0
        if self.last_disk_io and self.last_net_io:
            disk_read_rate = (disk.read_bytes - self.last_disk_io.read_bytes) / elapsed / (1024 * 1024)
            disk_write_rate = (disk.write_bytes - self.last_disk_io.write_bytes) / elapsed / (1024 * 1024)
            upload_rate = (net.bytes_sent - self.last_net_io.bytes_sent) / elapsed / 1024
            download_rate = (net.bytes_recv - self.last_net_io.bytes_recv) / elapsed / 1024
        self.last_disk_io = disk
        self.last_net_io = net
        self.last_io_time = now

        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk_usage = psutil.disk_usage(Path.home().anchor or "/")
        uptime_seconds = max(time.time() - psutil.boot_time(), 0)

        cpu_temp = None
        gpu_temp = None
        try:
            for sensor_name, entries in (psutil.sensors_temperatures() or {}).items():
                for entry in entries:
                    label = (entry.label or sensor_name).lower()
                    if cpu_temp is None and ("cpu" in label or "core" in label or "package" in label):
                        cpu_temp = entry.current
                    if gpu_temp is None and "gpu" in label:
                        gpu_temp = entry.current
        except (AttributeError, OSError):
            pass

        storage_percent = round(disk_usage.percent, 1)
        if storage_percent >= 95:
            disk_health = "Critical"
        elif storage_percent >= 85:
            disk_health = "Warning"
        else:
            disk_health = "Healthy"

        return {
            "timestamp": now.isoformat(),
            "cpu": round(psutil.cpu_percent(interval=0.2), 1),
            "memory": round(memory.percent, 1),
            "memory_used_gb": round(memory.used / (1024 ** 3), 2),
            "memory_total_gb": round(memory.total / (1024 ** 3), 2),
            "swap_percent": round(swap.percent, 1),
            "swap_used_gb": round(swap.used / (1024 ** 3), 2),
            "swap_total_gb": round(swap.total / (1024 ** 3), 2),
            "storage_used_gb": round(disk_usage.used / (1024 ** 3), 1),
            "storage_total_gb": round(disk_usage.total / (1024 ** 3), 1),
            "storage_percent": storage_percent,
            "disk_health": disk_health,
            "processes": len(psutil.pids()),
            "connections": connections,
            "disk_read_mb_s": round(max(disk_read_rate, 0), 2),
            "disk_write_mb_s": round(max(disk_write_rate, 0), 2),
            "upload_kb_s": round(max(upload_rate, 0), 1),
            "download_kb_s": round(max(download_rate, 0), 1),
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "uptime_seconds": round(uptime_seconds),
            "cpu_temp": round(cpu_temp, 1) if cpu_temp is not None else None,
            "gpu_temp": round(gpu_temp, 1) if gpu_temp is not None else None,
        }

    def scan_processes(self):
        process_rows = []
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent"]):
            try:
                data = proc.info
                pid = data["pid"]
                name = data.get("name") or "Unknown"
                self.seen_processes.add(pid)
                process_rows.append(
                    {
                        "pid": pid,
                        "name": name,
                        "username": data.get("username") or "Unknown",
                    }
                )
                if pid in self.process_alerts:
                    continue
                # Skip system processes that always show high resource usage
                if name.lower() in SKIP_RESOURCE_NAMES:
                    continue
                proc_info = {
                    "pid": pid,
                    "name": name,
                    "username": data.get("username") or "Unknown",
                    "cmdline": " ".join(data.get("cmdline") or []),
                    "cpu": round(data.get("cpu_percent") or 0, 1),
                    "memory": round(data.get("memory_percent") or 0, 1),
                    "parent_chain": self.parent_chain(proc),
                }
                event = self.engine.inspect_process(proc_info)
                if event:
                    self.process_alerts.add(pid)
                    asyncio.run_coroutine_threadsafe(self.record(event), self.loop)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        return self.activity.diff(process_rows)

    @staticmethod
    def parent_chain(proc, depth: int = 5) -> list[str]:
        chain = []
        current = proc
        for _ in range(depth):
            try:
                current = current.parent()
                if not current:
                    break
                chain.append(current.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                break
        return chain

    def _dedup_key(self, event: dict) -> tuple:
        metadata = event.get("metadata") or {}
        proc_name = metadata.get("name") or ""
        return (event.get("event_type", ""), event.get("title", ""), proc_name)

    def _is_duplicate(self, event: dict) -> bool:
        key = self._dedup_key(event)
        now = time.monotonic()
        last = self._alert_dedup.get(key, 0)
        if now - last < self._alert_cooldown:
            return True
        self._alert_dedup[key] = now
        return False

    async def record(self, event: dict):
        # Time-based dedup: prevent the same event signature from being stored repeatedly
        if self._is_duplicate(event):
            return
        self.db.add_event(event)
        await self.publish({"kind": "alert", "data": event})

        if event.get("source") in {"usb-monitor", "usb-security-engine"} or event.get("category") == "usb-security":
            usb_activity = self._make_usb_activity(event)
            self.usb_activity = [usb_activity, *self.usb_activity][:120]
            await self.publish({"kind": "activity", "data": [usb_activity]})

        if event.get("source") == "usb-monitor":
            self.telemetry.log_stream.add(self._make_usb_log_entry(event))
        
        if should_notify(event):
            notify(event)

        correlated = self.engine.correlate(event)
        if correlated:
            self.db.add_event(correlated)
            await self.publish({"kind": "alert", "data": correlated})
            if should_notify(correlated):
                notify(correlated)

    def _make_usb_log_entry(self, event: dict) -> dict:
        return {
            "timestamp": event["timestamp"],
            "log_name": "USB",
            "event_id": "USB",
            "source": event["source"],
            "level": "information",
            "message": event["summary"],
            "suspicious": True,
            "record": event["metadata"].get("device_id") or event["metadata"].get("path") or event["metadata"].get("pnp_id") or "usb",
        }

    def _make_usb_activity(self, event: dict) -> dict:
        metadata = event.get("metadata", {})
        device = metadata.get("device") or metadata
        scan = metadata.get("scan") or {}
        findings = scan.get("findings") or []
        return {
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

    def emit_threadsafe(self, event: dict):
        asyncio.run_coroutine_threadsafe(self.record(event), self.loop)

    def stop(self):
        self.running = False
        self.telemetry.stop()

    def active_processes(self, limit: int = 24) -> list[dict]:
        return self.resources.collect(limit)

    def recent_activity(self, limit: int = 30) -> list[dict]:
        return self.activity.list_recent(limit)

    def recent_usb_activity(self, limit: int = 30) -> list[dict]:
        return self.usb_activity[:limit]
