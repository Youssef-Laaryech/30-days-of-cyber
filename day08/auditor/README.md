# Day 08 — Linux CIS Hardening Auditor

## What I Built

A Linux security auditor that checks a system against 21 CIS Benchmark controls, produces a scored compliance report, maps each check to real-world frameworks (CIS, ISO 27001, NIST 800-53), and provides remediation commands for every failure. Written in Python, runs on Linux (or WSL on Windows).

---

## How It Works

```
python3 auditor.py   (inside WSL or on a Linux machine)
```

The tool runs a series of checks against the live system, each returning **PASS**, **FAIL**, or **WARN**, then calculates an overall compliance score and lists fixes for anything that failed.

Example output:
```
=============================================
  CIS HARDENING AUDITOR
=============================================
  [PASS] SSH root login is disabled (CIS 5.2.10)
  [PASS] SSH password authentication is disabled (CIS 5.2.11)
  [FAIL] UFW firewall is NOT active (CIS 3.5.1.1)
  ...
=============================================
  SUMMARY
=============================================
  Passed:   20
  Failed:   0
  Warnings: 1
  Compliance Score: 95.2%
=============================================
  REMEDIATION GUIDANCE
=============================================
  [!] UFW firewall is NOT active
      Fix: Run: sudo ufw enable
```

---

## What is CIS Hardening?

**CIS (Center for Internet Security)** publishes benchmarks — detailed security configuration guides for operating systems. A CIS benchmark for Ubuntu contains 100+ specific controls covering filesystem, services, network, logging, authentication, and system maintenance.

A **hardening auditor** checks the system against these controls automatically, so you know exactly what's secure and what needs fixing. Then you **remediate** (fix the failures) and **re-audit** to confirm — the standard security workflow.

---

## The 21 Checks (by CIS Section)

### Section 3 — Network Configuration
| Check | CIS Ref | What it verifies |
|-------|---------|------------------|
| IP forwarding disabled | 3.2.1 | Machine won't route traffic (anti-pivot) |
| TCP SYN cookies enabled | 3.3.9 | Protects against SYN flood DoS |
| UFW firewall active | 3.5.1.1 | Default-deny network protection |

### Section 4 — Logging & Auditing
| Check | CIS Ref | What it verifies |
|-------|---------|------------------|
| auditd running | 4.1.1.1 | System audit logging active |

### Section 5 — Access, Authentication & Authorization
| Check | CIS Ref | What it verifies |
|-------|---------|------------------|
| Crontab permissions (600) | 5.1.2 | Only root can edit scheduled jobs |
| SSH MaxAuthTries ≤ 4 | 5.2.7 | Limits brute-force login attempts |
| SSH empty passwords disabled | 5.2.9 | No blank-password logins |
| SSH root login disabled | 5.2.10 | Can't log in directly as root |
| SSH password auth disabled | 5.2.11 | Forces key-based auth |
| SSH idle timeout configured | 5.2.16 | Disconnects idle sessions |
| Password max age ≤ 365 | 5.4.1.1 | Forces periodic password change |
| Password min age ≥ 1 | 5.4.1.2 | Prevents rapid password cycling |
| Password warn age ≥ 7 | 5.4.1.3 | Warns users before expiry |
| Default umask 027 | 5.4.5 | New files aren't world-readable |

### Section 6 — System Maintenance
| Check | CIS Ref | What it verifies |
|-------|---------|------------------|
| /etc/passwd permissions (644) | 6.1.2 | User list not world-writable |
| /etc/shadow permissions (640) | 6.1.3 | Password hashes protected |
| /etc/group permissions (644) | 6.1.4 | Group file not world-writable |
| /etc/gshadow permissions (640) | 6.1.5 | Group passwords protected |
| No empty passwords | 6.2.1 | No accounts without passwords |
| No duplicate UIDs | 6.2.5 | Each user has a unique ID |
| Only root has UID 0 | 6.2.9 | Only root has superuser power |

---

## Framework Mapping

Each CIS control also satisfies requirements in other compliance frameworks. This is how professional auditors report — one check covers multiple standards.

| CIS Check | ISO 27001 | NIST 800-53 |
|-----------|-----------|-------------|
| SSH root login (5.2.10) | A.9.2.3 | AC-6 |
| SSH password auth (5.2.11) | A.9.4.2 | IA-2, IA-5 |
| SSH MaxAuthTries (5.2.7) | A.9.4.2 | AC-7 |
| File permissions (6.1.x) | A.9.2.3 | AC-3, AC-6 |
| Shadow permissions (6.1.3) | A.10.1 | IA-5, SC-28 |
| IP forwarding (3.2.1) | A.13.1 | SC-7 |
| SYN cookies (3.3.9) | A.13.1 | SC-5 |
| Empty passwords (6.2.1) | A.9.4.3 | IA-5 |
| Duplicate UIDs (6.2.5) | A.9.2.1 | IA-4 |
| Root UID (6.2.9) | A.9.2.3 | AC-6 |
| Password policy (5.4.x) | A.9.4.3 | IA-5 |
| Firewall (3.5.1.1) | A.13.1.1 | SC-7 |
| auditd (4.1.1.1) | A.12.4 | AU-2, AU-12 |

**The standards:**
- **CIS Benchmarks** — the specific technical hardening controls
- **ISO 27001** — international security management standard (Annex A controls). Companies get "ISO 27001 certified."
- **NIST 800-53** — US federal control catalog. Families: AC (Access Control), IA (Identification & Authentication), SC (System & Communications Protection), AU (Audit).

---

## Remediation

Every failed check produces a specific fix command in the output. Example workflow — hardened a WSL system from 58% to 95%:

```bash
sudo ufw enable                                              # firewall
echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config # SSH root
echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config
sudo chmod 600 /etc/crontab                                  # cron perms
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
echo "UMASK 027" | sudo tee -a /etc/login.defs               # umask
```

Audit → remediate → re-audit until compliant.

---

## What I Learned

- **CIS Benchmarks** — the industry-standard hardening framework and its section structure
- **Compliance mapping** — how one control satisfies CIS, ISO 27001, and NIST at once
- **Linux security internals** — SSH config, file permissions, password policy, kernel network params, sudo/root
- **`subprocess`** — running Linux commands from Python and parsing output
- **The audit-remediate-verify cycle** — how security engineers actually harden systems
- **WSL** — running a real Linux environment inside Windows

---

## Full Professional Checklist (for reference)

A complete production audit (like Lynis, CIS-CAT, OpenSCAP) covers 100+ controls:

- **Section 1 (Filesystem/Boot):** unused filesystems disabled, separate partitions, mount options (nodev/nosuid/noexec), sticky bit, GRUB password, AIDE file integrity
- **Section 2 (Services):** disable telnet/rsh/ftp/avahi/cups/nfs/samba/snmp, time sync configured
- **Section 3 (Network):** all done here + ICMP redirects, source routing, IPv6 RA
- **Section 4 (Logging):** auditd rules for privileged commands/file access/user changes, rsyslog/journald, remote logging, log permissions
- **Section 5 (Auth):** PAM password quality, faillock lockout, pwhistory, strong SSH ciphers/MACs/KEX
- **Section 6 (Maintenance):** world-writable files, unowned files, duplicate GIDs, root PATH, home dir permissions

**Tools used in industry:** Lynis, CIS-CAT Pro, OpenSCAP, Nessus, Ansible hardening roles

---

## Requirements

- Linux system or WSL (Windows Subsystem for Linux)
- Python 3
- Some checks require `sudo` (reading `/etc/shadow`, SSH config)

**Note on WSL:** The `auditd` check will warn on WSL because WSL lacks the full kernel audit subsystem. On a real Linux server or VM, this check works normally.

---

## Project Structure

```
auditor/
├── auditor.py    # The CIS hardening auditor (21 checks)
└── README.md     # This file
```

---

**#30DaysOfCyber**
