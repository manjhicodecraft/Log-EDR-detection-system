"""
Performance Optimizer Engine
-----------------------------
Scans running processes, identifies resource-heavy tasks that are safe to stop,
and allows safe termination — while strictly protecting all Windows-critical processes.

Safety: CRITICAL_PROCESSES is checked before EVERY kill operation.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import psutil


# ─────────────────────────────────────────────────────────────────────────────
# Windows-critical processes — NEVER kill these, even if they use high resources
# ─────────────────────────────────────────────────────────────────────────────
CRITICAL_PROCESSES: set[str] = {
    # Windows kernel / core
    "system", "system idle process", "registry", "memory compression", "idle",
    "csrss.exe", "winlogon.exe", "smss.exe", "lsass.exe", "services.exe",
    "svchost.exe", "wininit.exe", "dwm.exe", "explorer.exe", "conhost.exe",
    "runtimebroker.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "wmiprvse.exe", "spoolsv.exe", "lsm.exe", "dasHost.exe", "dashost.exe",
    "lsaiso.exe", "secure system", "memcompression.exe",

    # Windows security / Defender
    "msmpeng.exe", "securityhealthservice.exe", "nissrv.exe",
    "securityhealthsystray.exe", "mpcmdrun.exe", "msseces.exe",

    # Windows shell / UI host
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "ctfmon.exe", "applicationframehost.exe",
    "systemsettings.exe", "windowsinternal.composableshell.experiences.textinput.inputapp.exe",
    "lockapp.exe", "logonui.exe", "useroobebroker.exe",

    # Windows services
    "trustedinstaller.exe", "tiworker.exe", "wermgr.exe", "werfault.exe",
    "compattelrunner.exe", "diagtrack.dll", "diagtrackrunner.exe",
    "mousocoreworker.exe", "usocoreworker.exe", "uhssvc.exe",

    # GPU / display
    "nvcontainer.exe", "igfxCUIService.exe".lower(), "igfxuiservice.exe",
    "atiesrxx.exe", "atiesiexe.exe", "nvdisplay.container.exe",
    "igfxem.exe", "gfxdownloadwrapper.exe",

    # Network / system
    "nsi.exe", "dhcpcsvc.exe", "dnscache", "iphlpsvc", "netprofm",
    "wlanext.exe", "wlms.exe", "audiodg.exe",

    # WMI / COM
    "unsecapp.exe", "dllhost.exe", "msdtc.exe", "vds.exe",

    # Windows Store / Edge core
    "microsoftedgecp.exe", "microsoftedge.exe",

    # Virtualization
    "vmcompute.exe", "vmms.exe", "vmwp.exe", "hvhost.exe",

    # Authentication
    "lsaiso.exe", "ngciso.exe", "credentialenrollmentmanager.exe",
    "clipup.exe", "sppsvc.exe", "clipsp.sys",
}

# Normalize all to lowercase for comparison
CRITICAL_PROCESSES = {p.lower() for p in CRITICAL_PROCESSES}


# ─────────────────────────────────────────────────────────────────────────────
# Optimizable process categories — processes that can be safely stopped
# ─────────────────────────────────────────────────────────────────────────────
OPTIMIZABLE_CATEGORIES: dict[str, dict[str, list[str]]] = {
    "browser": {
        "processes": [
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
            "opera.exe", "vivaldi.exe", "waterfox.exe", "yandex.exe",
        ],
        "reason": "Web browsers consume high memory per tab",
        "risk": "moderate",  # may have unsaved tabs
    },
    "messaging": {
        "processes": [
            "discord.exe", "slack.exe", "teams.exe", "msteams.exe",
            "telegram.exe", "whatsapp.exe", "signal.exe", "skype.exe",
            "signal.exe", "line.exe",
        ],
        "reason": "Messaging apps running in background",
        "risk": "safe",
    },
    "media": {
        "processes": [
            "spotify.exe", "spotifywebhelper.exe", "vlc.exe",
            "itunes.exe", "wmplayer.exe", "audacity.exe",
        ],
        "reason": "Media player running in background",
        "risk": "safe",
    },
    "cloud-sync": {
        "processes": [
            "onedrive.exe", "googledrivesync.exe", "dropbox.exe",
            "icloud.exe", "megasync.exe", "boxsync.exe", "syncthing.exe",
        ],
        "reason": "Cloud sync client consuming bandwidth and disk I/O",
        "risk": "safe",
    },
    "updater": {
        "processes": [
            "googleupdate.exe", "microsoftedgeupdate.exe", "adobearm.exe",
            "adobegcclient.exe", "adobeipcbroker.exe", "creative cloud.exe",
            "gog galaxy.exe", "steamservice.exe", "steam.exe", "epicgameslauncher.exe",
            "uplay.exe", "battlenet.exe",
        ],
        "reason": "Background updater or game launcher",
        "risk": "safe",
    },
    "office": {
        "processes": [
            "excel.exe", "winword.exe", "powerpnt.exe", "outlook.exe",
            "msaccess.exe", "onenote.exe", "lync.exe",
        ],
        "reason": "Office application with high resource usage",
        "risk": "moderate",  # unsaved documents
    },
    "dev-tools": {
        "processes": [
            "node.exe", "python.exe", "python3.exe", "java.exe",
            "javaw.exe", "ruby.exe", "php.exe", "docker.exe",
            "dockerd.exe", "wsl.exe", "wslhost.exe",
        ],
        "reason": "Development tool consuming high CPU/RAM",
        "risk": "moderate",  # may be running a server
    },
    "remote": {
        "processes": [
            "anydesk.exe", "teamviewer.exe", "rustdesk.exe",
            "logmein.exe", "splashtop.exe", "ultravnc.exe",
        ],
        "reason": "Remote desktop tool running",
        "risk": "safe",
    },
    "misc": {
        "processes": [
            "notepad++.exe", "sublime_text.exe", "code.exe", "cursor.exe",
            "thunderbird.exe", "filezilla.exe", "putty.exe",
        ],
        "reason": "Application with high resource usage",
        "risk": "safe",
    },
}

# Build reverse lookup: process_name -> category
_PROCESS_TO_CATEGORY: dict[str, str] = {}
for _cat, _info in OPTIMIZABLE_CATEGORIES.items():
    for _proc in _info["processes"]:
        _PROCESS_TO_CATEGORY[_proc.lower()] = _cat


class PerformanceOptimizer:
    """Scans processes, classifies as protected or optimizable, and safely terminates them."""

    def scan_optimizable(self) -> dict:
        """Scan all running processes and classify them.

        Returns:
            {
                "optimizable": [...],  # safe to stop
                "protected": [...],    # Windows-critical, skipped
                "summary": {optimizable_count, protected_count, cpu_saved_pct, ram_saved_mb},
                "timestamp": "...",
            }
        """
        optimizable: list[dict] = []
        protected: list[dict] = []
        seen_names: set[str] = set()

        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "cmdline", "username"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info.get("name") or "Unknown"
                name_lower = name.lower()
                cpu = info.get("cpu_percent") or 0
                mem_pct = info.get("memory_percent") or 0

                # Skip very low-resource processes
                if cpu < 1.5 and mem_pct < 0.5:
                    continue

                # Check if critical
                if name_lower in CRITICAL_PROCESSES:
                    if name_lower not in seen_names:
                        seen_names.add(name_lower)
                        protected.append({
                            "pid": pid,
                            "name": name,
                            "cpu": round(cpu, 1),
                            "ram_mb": self._get_ram_mb(proc),
                            "reason": "Windows-critical — protected",
                        })
                    continue

                # Check if optimizable
                category = _PROCESS_TO_CATEGORY.get(name_lower)
                if category:
                    cat_info = OPTIMIZABLE_CATEGORIES[category]
                    mem = self._get_ram_mb(proc)

                    # Only flag if resource usage is meaningful
                    if cpu < 2.0 and mem < 30:
                        continue

                    optimizable.append({
                        "pid": pid,
                        "name": name,
                        "category": category,
                        "cpu": round(cpu, 1),
                        "ram_mb": round(mem, 1),
                        "memory_pct": round(mem_pct, 1),
                        "instances": 1,
                        "risk": cat_info["risk"],
                        "reason": cat_info["reason"],
                        "username": info.get("username") or "Unknown",
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        # Aggregate by process name
        optimizable = self._aggregate(optimizable)

        # Sort: high CPU first, then high RAM
        optimizable.sort(key=lambda x: x["cpu"] + x["memory_pct"], reverse=True)

        cpu_saved = sum(p["cpu"] for p in optimizable)
        ram_saved = sum(p["ram_mb"] for p in optimizable)
        safe_count = sum(1 for p in optimizable if p["risk"] == "safe")
        moderate_count = sum(1 for p in optimizable if p["risk"] == "moderate")

        return {
            "optimizable": optimizable[:30],  # limit to top 30
            "protected": protected[:20],
            "summary": {
                "optimizable_count": len(optimizable),
                "protected_count": len(protected),
                "safe_to_stop": safe_count,
                "moderate_risk": moderate_count,
                "cpu_saved_pct": round(cpu_saved, 1),
                "ram_saved_mb": round(ram_saved, 1),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def kill_process(self, pid: int, expected_name: str = "") -> dict:
        """Safely terminate a process by PID.

        Safety checks:
        1. Re-read process name from PID — reject if critical
        2. Verify name matches expected (prevent PID-reuse attacks)
        3. Graceful terminate first, force-kill after 3s timeout
        """
        try:
            proc = psutil.Process(pid)
            actual_name = proc.name().lower()

            # Safety check 1: Is this a critical process?
            if actual_name in CRITICAL_PROCESSES:
                return {
                    "success": False,
                    "error": f"BLOCKED: {actual_name} is a Windows-critical process and cannot be stopped.",
                    "pid": pid,
                    "name": actual_name,
                }

            # Safety check 2: Does the name match what the frontend expects?
            if expected_name and actual_name != expected_name.lower():
                return {
                    "success": False,
                    "error": f"BLOCKED: PID {pid} is now {actual_name}, not {expected_name}. PID may have been reused.",
                    "pid": pid,
                    "name": actual_name,
                }

            # Graceful terminate
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

            return {
                "success": True,
                "pid": pid,
                "name": actual_name,
                "message": f"Terminated {actual_name} (PID {pid})",
            }

        except psutil.NoSuchProcess:
            return {"success": False, "error": f"Process {pid} no longer exists.", "pid": pid}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied to kill PID {pid}. Run as administrator.", "pid": pid}
        except Exception as exc:
            return {"success": False, "error": f"Failed to kill PID {pid}: {exc}", "pid": pid}

    def kill_all_safe(self) -> dict:
        """Kill all 'safe' rated optimizable processes (not 'moderate' risk)."""
        scan = self.scan_optimizable()
        results = []
        killed = 0
        failed = 0

        for proc_info in scan["optimizable"]:
            if proc_info["risk"] != "safe":
                continue
            for pid in proc_info.get("pids", [proc_info["pid"]]):
                result = self.kill_process(pid, proc_info["name"])
                results.append(result)
                if result["success"]:
                    killed += 1
                else:
                    failed += 1

        return {
            "killed": killed,
            "failed": failed,
            "skipped_moderate": sum(1 for p in scan["optimizable"] if p["risk"] == "moderate"),
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def estimate_risk_reduction(self, current_score: int) -> dict:
        """Estimate how much risk score would drop after optimization."""
        if current_score <= 0:
            return {"estimated_reduction": 0, "new_score": 0}

        scan = self.scan_optimizable()
        # Each stopped process reduces noise and potential threat events
        # Heuristic: each high-resource process stopped reduces score by ~2-5 points
        safe_count = scan["summary"]["safe_to_stop"]
        moderate_count = scan["summary"]["moderate_risk"]

        reduction = min(safe_count * 3 + moderate_count * 2, 40)  # cap at 40 points
        new_score = max(current_score - reduction, 0)

        return {
            "estimated_reduction": reduction,
            "new_score": new_score,
            "current_score": current_score,
            "processes_stopped": safe_count + moderate_count,
        }

    @staticmethod
    def _get_ram_mb(proc) -> float:
        try:
            return proc.memory_info().rss / (1024 * 1024)
        except (psutil.AccessDenied, AttributeError, OSError):
            return 0.0

    @staticmethod
    def _aggregate(processes: list[dict]) -> list[dict]:
        """Group processes by name, sum resources, collect PIDs."""
        groups: dict[str, dict] = {}
        for p in processes:
            key = p["name"].lower()
            if key not in groups:
                groups[key] = {**p, "pids": [p["pid"]]}
            else:
                g = groups[key]
                g["cpu"] += p["cpu"]
                g["ram_mb"] += p["ram_mb"]
                g["memory_pct"] += p["memory_pct"]
                g["instances"] += 1
                g["pids"].append(p["pid"])

        for g in groups.values():
            g["cpu"] = round(g["cpu"], 1)
            g["ram_mb"] = round(g["ram_mb"], 1)
            g["memory_pct"] = round(g["memory_pct"], 1)
            g["pids"] = sorted(g["pids"])

        return list(groups.values())
