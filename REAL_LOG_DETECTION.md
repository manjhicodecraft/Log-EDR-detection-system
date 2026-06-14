# Real-Time Log Detection — Trinetra Sentinel

The Trinetra Sentinel desktop app continuously monitors Windows Event Logs to detect
suspicious system behavior and alert you immediately via the Electron dashboard and
desktop popup notifications.

---

## Features

### 1. Windows Event Log Monitoring

The tool monitors **five** event log sources in real-time:

- **Security Log** — Failed logins (4625), account lockouts (4740), brute-force detection
- **System Log** — Service failures, driver errors, critical system events
- **Application Log** — Application crashes, errors, threat keyword patterns
- **Setup Log** — OS installation and update events
- **Windows PowerShell Log** — PowerShell execution events

**Monitored Event Patterns:**
- Critical System Errors (Event Type 1)
- System Warnings (Event Type 2)
- Application Crashes (Event IDs 1000, 1001, 1002, 1008)
- Service Failures (Event IDs 7000, 7001, 7009, 7011, 7031, 7032, 7034, 7035, 7036)
- Threat Keywords (malware, trojan, ransom, encrypt, payload, backdoor, exploit, etc.)

### 2. Detection Pipeline

```
Every ~3 seconds (in monitor loop):
  1. Windows Event Logs → read new records since last poll
  2. Parse event ID, source, message, severity
  3. Match against suspicious patterns
  4. Create threat event with score + severity
  5. Log to notifications.log
  6. Desktop popup notification (if High/Critical)
  7. Broadcast to Electron dashboard via WebSocket
  8. Correlate with other recent events

Correlation:
  IF 3+ different threat categories within 5 minutes
    → Create "Correlated Intrusion Pattern" alert (score: 70)
    → Critical desktop notification
```

### 3. Log Stream Buffer

- 300-entry ring buffer in memory
- Bootstrap: loads 150 recent records on startup (12-hour window)
- Real-time push via WebSocket every ~3 seconds
- Polling backup: frontend polls `/api/logs/recent` every 4 seconds
- `LogStreamBuffer` with monotonic sequence numbers for incremental reads

---

## Dashboard Integration

Open the Trinetra Sentinel **Desktop App** (`run_trinetra_desktop.bat`):

| Section | What to Look For |
|---------|-----------------|
| **Log Detection** | Real-time Event Log stream (System, Application, Security, Setup, PowerShell) |
| **Collector Health** | `windows_security`, `application_logs` status indicators |
| **Live Threat Feed** | All detected events with severity colors |
| **Alert Timeline** | Bar chart of alert frequency over time |

---

## Threat Scoring

Events are scored 0-100 with automatic severity calculation:

| Score | Severity | Action |
|-------|----------|--------|
| 80-100 | Critical | Desktop popup + error sound + dashboard alert |
| 50-79 | High | Desktop popup + warning sound + dashboard alert |
| 20-49 | Medium | Dashboard alert |
| 0-19 | Low | Dashboard alert (filtered from main feed) |

---

## Verification

Check that logs are being monitored in the **Collector Health** panel:
- `windows_security` → Active (authentication monitoring)
- `application_logs` → Active (System, Application, Setup, PowerShell logs)
- `file_activity` → Active (ransomware detection)
- `usb_devices` → Active (USB tracking)
- `startup_registry` → Active (persistence detection)

---

## Tips

- **High alert volume?** System logs are verbose. The tool filters for Error/Warning only, uses
  specific event IDs for service failures, and keyword-matches for threat detection.
- **Collector shows "Limited"?** Run as Administrator — Windows Event Log access may be restricted.
- **Check logs manually?** `Get-EventLog System -Newest 10 -EntryType Error` in PowerShell.
- **Monitor notifications:** `Get-Content -Path notifications.log -Tail 20 -Wait`
