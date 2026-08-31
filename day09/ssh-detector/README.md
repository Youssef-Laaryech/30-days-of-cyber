# Day 09 — SSH Brute Force Detector

## What I Built

A log analysis tool that detects SSH brute force attacks by parsing authentication logs, classifying threats by severity, mapping them to MITRE ATT&CK techniques, and exporting SIEM-ready alerts. Includes both batch analysis and real-time live monitoring modes.

---

## How It Works

```
python3 detector.py
```

Choose:
1. **Analyze existing log** — parse a log file, detect attacks, score severity, export JSON
2. **Live monitor** — watch the log in real-time for new failed logins (like fail2ban)

Example output:
```
--- ALERTS ---
  [CRITICAL] 185.220.101.45 (no PTR record)
    Failed attempts: 8
    Burst: 8 failures within 120s  Automated: True
    Usernames tried: admin, administrator, guest, root, support
    Login succeeded: True
    MITRE: T1110 Brute Force, T1110.003 Password Spraying, T1078 Valid Accounts
    Action: sudo ufw deny from 185.220.101.45
```

---

## What is a Brute Force Attack?

An attacker tries thousands of username/password combinations to break into SSH. Every failed attempt is logged. This tool reads those logs, spots the pattern (many failures from one IP), and flags the attacker.

---

## Detection Features

### Failure Counting
Parses `/var/log/auth.log` (or a sample) and counts failed login attempts per source IP.

### Threshold Detection
Flags any IP exceeding the failure threshold (default 5). Below that is treated as normal human error.

### Time-Window / Burst Detection
Uses a sliding-window algorithm to find the most failures packed into a short time (default 120s). Rapid bursts indicate automated bots vs. slow attempts that might be human.

### Password Spraying Detection
Detects one IP trying many different usernames (a key attack signal). Your sample attacker tried oracle, postgres, git, ubuntu, root.

### Breach Detection
The most critical alert: if an IP had many failures then a SUCCESS, the attacker likely got in.

### Reverse DNS Lookup
Resolves each attacker IP to a hostname (builds on Day 03 DNS project) to identify who owns it.

### Whitelisting
Skips trusted internal IP ranges (192.168.x, 10.x, 172.16.x) to avoid blocking legitimate users.

### Live Monitoring
Watches the log continuously like `tail -f`, catching new failed logins in real-time — how a real detector runs 24/7 on a server.

---

## MITRE ATT&CK Mapping

Alerts are tagged with the industry-standard attack technique catalog:

| Technique | ID | When it fires |
|-----------|-----|---------------|
| Brute Force | T1110 | Failures exceed threshold |
| Password Spraying | T1110.003 | 3+ different usernames from one IP |
| Valid Accounts | T1078 | Successful login after failures (breach) |

## Severity Model (NIST 800-61)

| Severity | Condition |
|----------|-----------|
| CRITICAL | Attack succeeded (breach) |
| HIGH | Threshold hit + spraying or rapid burst |
| MEDIUM | Threshold hit |
| LOW | Below threshold (not alerted) |

---

## SIEM Integration

Alerts are exported to `alerts.json` in structured format. This is how detection tools feed into a SIEM (Security Information and Event Management system). Each alert has source IP, severity, MITRE tags, and recommended action — ready for automated response or dashboard ingestion. (Sets up Day 14 — Mini SIEM.)

---

## What I Learned

- **Log parsing** — extracting IPs, usernames, and timestamps with regular expressions
- **Pattern detection** — distinguishing attacks from normal user error
- **Sliding-window algorithm** — measuring event frequency over time
- **MITRE ATT&CK** — the standard framework for classifying attacker techniques
- **Severity triage** — how SOC analysts prioritize incidents (NIST 800-61)
- **Reverse DNS** — identifying who owns an attacking IP
- **Live file monitoring** — reading a growing log in real-time (`tail -f` behavior)
- **Structured alerting** — JSON output for SIEM/automation pipelines
- **Whitelisting** — reducing false positives (NIST 800-94)

---

## Real-World Context

In production, this logic is what **fail2ban** provides. A deployed version would:
- Run as a systemd service 24/7
- Auto-execute firewall blocks on detection
- Send alerts via email/Slack/webhook
- Handle log rotation
- Auto-unblock IPs after a cooldown period

---

## Frameworks Referenced

| Framework | Relevance |
|-----------|-----------|
| **MITRE ATT&CK** | Technique classification (T1110, T1078) |
| **NIST 800-61** | Incident severity classification |
| **NIST 800-94** | Intrusion detection guidance (whitelisting, thresholds) |

---

## Testing the Live Mode

The included `auth.log` is a sample with realistic attack patterns. To simulate a live attack (run both inside WSL/Linux):

Terminal 1: `python3 detector.py` → pick option 2
Terminal 2: `echo "Feb 10 14:00:00 server sshd[9999]: Failed password for root from 1.2.3.4 port 55 ssh2" >> auth.log`

The detector catches the new line instantly.

---

## Project Structure

```
ssh-detector/
├── detector.py    # The detector (batch + live modes)
├── auth.log       # Sample log with attack patterns
└── README.md      # This file
```

---

**#30DaysOfCyber**
