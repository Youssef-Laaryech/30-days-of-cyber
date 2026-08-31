import re
import json
import socket
import time
from datetime import datetime
from collections import defaultdict

# ---- Configuration ----
FAIL_THRESHOLD = 5          # failures before flagging brute force
SPRAY_THRESHOLD = 3         # unique usernames before flagging password spraying
TIME_WINDOW = 120           # seconds: failures this close = automated attack
WHITELIST = ["192.168.", "10.", "172.16."]   # trusted internal ranges
LOG_FILE = "auth.log"

# Current year (logs don't include the year, so we assume this year)
CURRENT_YEAR = datetime.now().year


def is_whitelisted(ip):
    """Skip trusted internal IPs to avoid false positives (NIST 800-94)."""
    for prefix in WHITELIST:
        if ip.startswith(prefix):
            return True
    return False


def parse_timestamp(line):
    """Extract the timestamp from a syslog line like 'Feb 10 09:15:33'."""
    match = re.match(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
    if match:
        try:
            return datetime.strptime(f"{CURRENT_YEAR} {match.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None


def reverse_dns(ip):
    """Look up the hostname for an IP (builds on Day 03 DNS project)."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "no PTR record"


def build_ip_data(lines):
    """Parse log lines into per-IP data with timestamps."""
    ip_data = defaultdict(lambda: {"failures": 0, "usernames": set(),
                                    "success": False, "times": []})
    for line in lines:
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        ts = parse_timestamp(line)

        if 'Failed password' in line:
            ip_data[ip]["failures"] += 1
            if ts:
                ip_data[ip]["times"].append(ts)
            user_match = re.search(r'for (?:invalid user )?(\w+) from', line)
            if user_match:
                ip_data[ip]["usernames"].add(user_match.group(1))
        elif 'Accepted password' in line:
            ip_data[ip]["success"] = True
    return ip_data


def max_burst(times):
    """Find the most failures that happened within TIME_WINDOW seconds."""
    if len(times) < 2:
        return len(times)
    times = sorted(times)
    best = 1
    start = 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > TIME_WINDOW:
            start += 1
        best = max(best, end - start + 1)
    return best


def score_severity(data, burst):
    """Assign severity (NIST 800-61 incident classification)."""
    failures = data["failures"]
    sprayed = len(data["usernames"]) >= SPRAY_THRESHOLD
    if data["success"] and failures >= FAIL_THRESHOLD:
        return "CRITICAL"
    if failures >= FAIL_THRESHOLD and (sprayed or burst >= FAIL_THRESHOLD):
        return "HIGH"
    if failures >= FAIL_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def analyze(ip_data):
    alerts = []
    for ip, data in ip_data.items():
        if is_whitelisted(ip):
            continue
        if data["failures"] < FAIL_THRESHOLD:
            continue

        burst = max_burst(data["times"])

        techniques = ["T1110 Brute Force"]
        if len(data["usernames"]) >= SPRAY_THRESHOLD:
            techniques.append("T1110.003 Password Spraying")
        if data["success"]:
            techniques.append("T1078 Valid Accounts (possible breach)")

        rapid = burst >= FAIL_THRESHOLD

        alert = {
            "source_ip": ip,
            "hostname": reverse_dns(ip),
            "failed_attempts": data["failures"],
            "max_burst": f"{burst} failures within {TIME_WINDOW}s",
            "automated": rapid,
            "usernames_tried": sorted(data["usernames"]),
            "login_succeeded": data["success"],
            "severity": score_severity(data, burst),
            "mitre_techniques": techniques,
            "recommended_action": f"sudo ufw deny from {ip}"
        }
        alerts.append(alert)
    return alerts


def print_report(ip_data, alerts):
    print("=" * 55)
    print("  SSH BRUTE FORCE DETECTOR")
    print("=" * 55)

    print("\n--- Failed Attempts Summary ---")
    for ip, data in sorted(ip_data.items(), key=lambda x: x[1]["failures"], reverse=True):
        tag = " (whitelisted)" if is_whitelisted(ip) else ""
        print(f"  {ip}: {data['failures']} failures{tag}")

    if not alerts:
        print("\n  No brute force attacks detected.")
        return

    print("\n--- ALERTS ---")
    for a in alerts:
        print(f"\n  [{a['severity']}] {a['source_ip']} ({a['hostname']})")
        print(f"    Failed attempts: {a['failed_attempts']}")
        print(f"    Burst: {a['max_burst']}  Automated: {a['automated']}")
        print(f"    Usernames tried: {', '.join(a['usernames_tried'])}")
        print(f"    Login succeeded: {a['login_succeeded']}")
        print(f"    MITRE: {', '.join(a['mitre_techniques'])}")
        print(f"    Action: {a['recommended_action']}")


def save_json(alerts):
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n  {len(alerts)} alert(s) saved to alerts.json")


def run_once():
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()
    ip_data = build_ip_data(lines)
    alerts = analyze(ip_data)
    print_report(ip_data, alerts)
    save_json(alerts)


def run_live():
    """Continuously watch the log for new lines (like tail -f)."""
    print("Live monitoring mode. Watching auth.log for new entries...")
    print("Press Ctrl+C to stop.\n")
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if 'Failed password' in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    print(f"  [LIVE] Failed login from {ip} ({reverse_dns(ip)})")


print("1. Analyze existing log")
print("2. Live monitor (watch for new entries)")
mode = input("Pick (1 or 2): ").strip()

if mode == "2":
    run_live()
else:
    run_once()
