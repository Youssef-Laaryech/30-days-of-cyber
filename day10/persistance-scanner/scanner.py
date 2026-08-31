import os
import re
import json

# Suspicious patterns with severity (higher = worse)
SUSPICIOUS_PATTERNS = [
    (r'/dev/tcp/', "Reverse shell (/dev/tcp)", "CRITICAL"),
    (r'bash\s+-i', "Interactive reverse shell", "CRITICAL"),
    (r'nc\s+.*-e', "Netcat with execute (backdoor)", "CRITICAL"),
    (r'python.*-c.*socket', "Python reverse shell", "CRITICAL"),
    (r'curl.*\|.*sh', "Curl piped to shell (payload download)", "HIGH"),
    (r'wget.*\|.*sh', "Wget piped to shell (payload download)", "HIGH"),
    (r'base64\s+-d', "Base64 decoding (obfuscation)", "MEDIUM"),
    (r'eval\s*\(', "eval() execution (obfuscation)", "MEDIUM"),
]

findings = []


def check_line(location, line, technique):
    """Test a line against all patterns; record any matches with MITRE technique."""
    for pattern, reason, severity in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line):
            findings.append({
                "location": location,
                "line": line.strip(),
                "reason": reason,
                "severity": severity,
                "mitre": technique
            })


def read_file_safe(path, technique):
    """Read a file line by line, skipping gracefully if not permitted."""
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                check_line(path, line, technique)
    except PermissionError:
        print(f"    (skipped, need root: {path})")
    except Exception:
        pass


def scan_files(paths, technique, label):
    """Generic scanner: reads each file/dir path and checks every line."""
    print(f"\n--- Scanning {label} ({technique}) ---")
    for path in paths:
        if os.path.isfile(path):
            read_file_safe(path, technique)
        elif os.path.isdir(path):
            try:
                entries = os.listdir(path)
            except PermissionError:
                print(f"    (skipped, need root: {path})")
                continue
            for filename in entries:
                fp = os.path.join(path, filename)
                if os.path.isfile(fp):
                    read_file_safe(fp, technique)


def scan_ssh_keys(paths, technique, label):
    """SSH authorized_keys: flag forced-command keys (backdoor with command=)."""
    print(f"\n--- Scanning {label} ({technique}) ---")
    for path in paths:
        if os.path.isfile(path):
            try:
                with open(path, 'r', errors='ignore') as f:
                    for line in f:
                        if 'command=' in line:
                            findings.append({
                                "location": path,
                                "line": line.strip()[:80],
                                "reason": "SSH key with forced command (backdoor)",
                                "severity": "HIGH",
                                "mitre": technique
                            })
                        check_line(path, line, technique)
            except PermissionError:
                print(f"    (skipped, need root: {path})")


def scan_real_system():
    scan_files(
        ['/etc/crontab', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
         '/etc/cron.weekly', '/etc/cron.monthly'],
        "T1053.003 Cron", "Cron Jobs")

    scan_files(
        ['/etc/systemd/system', '/usr/lib/systemd/system',
         os.path.expanduser('~/.config/systemd/user')],
        "T1543.002 Systemd Service", "Systemd Units")

    scan_files(
        [os.path.expanduser('~/.bashrc'), os.path.expanduser('~/.bash_profile'),
         os.path.expanduser('~/.profile'), '/etc/profile', '/etc/profile.d',
         '/etc/bash.bashrc'],
        "T1546.004 Shell RC", "Shell Init Files")

    scan_ssh_keys(
        [os.path.expanduser('~/.ssh/authorized_keys')],
        "T1098.004 SSH Keys", "SSH authorized_keys")

    scan_files(
        ['/etc/ld.so.preload'],
        "T1574.006 LD_PRELOAD", "LD_PRELOAD")


def scan_test_dir(directory):
    print(f"\n--- Scanning test directory: {directory} ---")
    for filename in os.listdir(directory):
        fp = os.path.join(directory, filename)
        if os.path.isfile(fp):
            with open(fp, 'r', errors='ignore') as f:
                for line in f:
                    check_line(fp, line, "TEST")


def print_report():
    print("\n" + "=" * 55)
    print("  PERSISTENCE SCAN RESULTS")
    print("=" * 55)
    if not findings:
        print("  No suspicious persistence mechanisms found.")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 3)):
        print(f"\n  [{f['severity']}] {f['location']}")
        print(f"    Command: {f['line']}")
        print(f"    Reason:  {f['reason']}")
        print(f"    MITRE:   {f['mitre']}")

    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"\n  Total: {len(findings)}  (CRITICAL: {crit}, HIGH: {high}, MEDIUM: {med})")


def save_json():
    if findings:
        with open("findings.json", "w") as f:
            json.dump(findings, f, indent=2)
        print(f"  {len(findings)} finding(s) saved to findings.json")


print("=" * 55)
print("  SYSTEMD PERSISTENCE SCANNER")
print("=" * 55)
print("\n1. Scan real system")
print("2. Scan a test directory")
mode = input("Pick (1 or 2): ").strip()

if mode == "2":
    test_dir = input("Enter test directory path: ").strip()
    if os.path.isdir(test_dir):
        scan_test_dir(test_dir)
    else:
        print(f"Directory not found: '{test_dir}'")
else:
    scan_real_system()

print_report()
save_json()
