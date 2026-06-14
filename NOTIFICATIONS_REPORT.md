# Trinetra Sentinel — Desktop Notifications Report

All notifications appear as **WPF popup windows** in the bottom-right corner of the
screen. These popups are native Windows desktop notifications — they appear even when
the Electron app window is not focused.

---

## Popup Design

```
┌─────────────────────────────────────────┐
│ ● TRINETRA SENTINEL — [SEVERITY LABEL]  │  ← Colored dot + label
│                                          │
│ Alert Title (white, bold)               │  ← Main alert title
│ Alert summary message text here...      │  ← Brief description
└─────────────────────────────────────────┘
   Dark background (#1A1A2E)
   Colored border matching severity
   Auto-closes after 6-8 seconds
```

### Severity Colors & Sounds

| Severity | Border Color | Sound | Auto-Close | Cooldown |
|----------|-------------|-------|------------|----------|
| Critical | Red (#FF4444) | Error beep (MB_ICONHAND) | 8 seconds | 15 seconds |
| High | Orange (#FF8800) | Warning beep (MB_ICONEXCLAMATION) | 6 seconds | 30 seconds |
| Medium | Yellow (#FFD700) | None | 6 seconds | 60 seconds |
| Low | Blue (#4488FF) | None | 6 seconds | 120 seconds |

---

## Complete Notification List

### 1. Critical Severity Popups

| Event Type | Popup Title | Trigger | Score |
|-----------|-------------|---------|-------|
| `ransomware_activity` | Ransomware-like file activity detected | 100+ writes, 25+ renames, or 15+ extension changes in 10s | 80 |
| *(score >= 80 any source)* | Automatic | Any event scoring 80+ | 80+ |

### 2. High Severity Popups

| Event Type | Popup Title | Trigger | Score |
|-----------|-------------|---------|-------|
| `threat_detected` | Potential threat detected in logs | Threat keywords in Windows event logs | 75 |
| `intrusion_correlation` | Correlated intrusion pattern | 3+ alert categories within 5 minutes | 70 |
| `system_error` | Critical system error: [source] | Error-level events from System log | 55 |
| `usb_threat_detected` | USB threat-like content detected | High-risk files on USB (autorun, malware) | 55 |
| `registry_persistence` | Startup registry entry modified | New/changed entry in `HKCU\...\Run` | 50 |
| `malware_signature` | Malware signature match | Known malware hash match | 50 |

### 3. Medium Severity Popups

| Event Type | Popup Title | Trigger | Score |
|-----------|-------------|---------|-------|
| `application_crash` | Application crash detected | Event IDs 1000-1008 | 45 |
| `mass_file_deletion` | Mass file deletion detected | 20+ files deleted in 12s | 45 |
| `suspicious_chain` | AI-origin shell process detected | Shell from AI tool parent chain | 45 |
| `powershell_encoded` | Encoded PowerShell execution | PowerShell with `-enc`, `frombase64`, etc. | 40 |
| `dangerous_command` | Dangerous command observed | `rm -rf`, `del /s`, `diskpart`, etc. | 40 |
| `service_failure` | Service failure: [name] | Event IDs 7000-7036 | 40 |
| `ai_assisted_command` | Dangerous command observed (AI) | Dangerous command from AI tool | 35 |
| `mass_file_rename` | Mass file rename detected | 30+ files renamed in 12s | 35 |
| `account_lockout` | Windows account lockout detected | Event ID 4740 | 35 |
| `usb_scan_suspicious` | USB scan found risky files | Medium-risk files on USB | 30 |
| `bulk_file_modification` | Bulk file modification detected | 50+ modifications in 12s | 30 |
| `usb_device` | USB storage device inserted | Any USB storage connected | 20 |
| `failed_login` | Repeated login failures detected | 5+ failed logins in 60s (4625) | 10 |

---

## Engine → Notification Mapping

| Engine | Notifications It Triggers |
|--------|--------------------------|
| System Activity Engine | Process open/close (dashboard only, no popup) |
| Resource Analyzer | High CPU/RAM → popup if severity is high |
| AI Attribution Engine | `ai_assisted_command`, `dangerous_command`, `suspicious_chain` |
| Code Protection Engine | `mass_file_deletion`, `mass_file_rename`, `bulk_file_modification` |
| USB Security Engine | `usb_device`, `usb_scan_suspicious`, `usb_threat_detected` |
| Threat Detection Engine | `powershell_encoded`, `suspicious_process`, `high_cpu`, `high_memory`, `anomaly` |
| Log Correlation Engine | `intrusion_correlation` |
| Windows Log Collectors | `system_error`, `application_crash`, `service_failure`, `threat_detected`, `failed_login`, `account_lockout` |
| Registry Monitor | `registry_persistence` |
| File Watcher | `ransomware_activity` |

---

## Cooldown Summary

| Severity | Cooldown | Max Popups/Hour |
|----------|----------|----------------|
| Critical | 15 seconds | ~240/hour |
| High | 30 seconds | ~120/hour |
| Medium | 60 seconds | ~60/hour |
| Low | 120 seconds | ~30/hour |

Cooldown is per (event_type + title) pair — different alert types can fire independently.

---

## Notification Log

All notifications are logged to `notifications.log` in the project root:

```
2026-06-09 12:55:48 - INFO - [CRITICAL] Ransomware-like file activity detected | Rapid file activity...
2026-06-09 12:55:48 - INFO - WPF popup sent: [CRITICAL] Ransomware-like file activity detected
2026-06-09 12:52:10 - INFO - [HIGH] Correlated intrusion pattern | Multiple suspicious behaviors...
```

This log persists across restarts and can be used for audit/review.
