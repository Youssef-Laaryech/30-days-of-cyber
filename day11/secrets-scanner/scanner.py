import os
import re
import math
import json
import subprocess

# ---- Method 1: Known secret patterns (name, regex, severity) ----
SECRET_PATTERNS = [
    ("AWS Access Key", r'AKIA[0-9A-Z]{16}', "CRITICAL"),
    ("GitHub Token", r'ghp_[0-9A-Za-z]{36}', "CRITICAL"),
    ("Slack Token", r'xox[baprs]-[0-9A-Za-z-]{10,}', "CRITICAL"),
    ("Stripe Secret Key", r'sk_(?:live|test)_[0-9A-Za-z]{24}', "CRITICAL"),
    ("Google API Key", r'AIza[0-9A-Za-z_-]{35}', "HIGH"),
    ("Private Key", r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "CRITICAL"),
    ("JWT Token", r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "HIGH"),
    ("Connection String", r'(?:postgres|mysql|mongodb)://[^:]+:[^@]+@', "HIGH"),
    ("Generic API Key", r'api[_-]?key["\s:=]+[0-9A-Za-z]{16,}', "MEDIUM"),
    ("Password Assignment", r'password["\s:=]+["\'][^"\']{6,}["\']', "MEDIUM"),
]

PLACEHOLDERS = ["your_", "xxxx", "example", "changeme", "placeholder",
                "dummy", "<", ">", "..."]

# Directories and file types to skip
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
IGNORE_EXTS = {".jpg", ".png", ".gif", ".pdf", ".zip", ".exe", ".pyc", ".so", ".bin"}

ENTROPY_THRESHOLD = 4.5
MIN_TOKEN_LEN = 20

# findings keyed by (file, line, content) to deduplicate; value tracks methods
findings = {}


def shannon_entropy(s):
    """Shannon entropy (bits per character) — measures randomness."""
    if not s:
        return 0.0
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(text):
    lower = text.lower()
    return any(ph in lower for ph in PLACEHOLDERS)


def redact(secret):
    """Mask the middle of a secret so the report doesn't leak it."""
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def add_finding(file, line_num, content, stype, severity, method):
    """Record a finding, merging duplicates and tracking detection methods."""
    key = (file, line_num, content)
    if key in findings:
        findings[key]["methods"].add(method)
    else:
        findings[key] = {
            "file": file,
            "line": line_num,
            "type": stype,
            "severity": severity,
            "content": redact(content),
            "methods": {method}
        }


def check_patterns(filepath, line_num, line):
    for name, pattern, severity in SECRET_PATTERNS:
        m = re.search(pattern, line)
        if m and not is_placeholder(line):
            add_finding(filepath, line_num, m.group(0), name, severity, "pattern")


def check_entropy(filepath, line_num, line):
    tokens = re.findall(r'[A-Za-z0-9+/=_\-]{%d,}' % MIN_TOKEN_LEN, line)
    for token in tokens:
        if is_placeholder(token):
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            add_finding(filepath, line_num, token,
                        f"High-entropy string", "LOW", "entropy")


def scan_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in IGNORE_EXTS:
        return
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                check_patterns(filepath, line_num, line)
                check_entropy(filepath, line_num, line)
    except Exception:
        pass


def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        # prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for filename in files:
            scan_file(os.path.join(root, filename))


def scan_git_history(repo_path):
    """Scan every git commit's changes for secrets (T1552 exposed credentials)."""
    print(f"\n--- Scanning git history: {repo_path} ---")
    try:
        commits = subprocess.run(
            ["git", "-C", repo_path, "log", "--all", "--pretty=format:%H"],
            capture_output=True, text=True).stdout.split()
    except Exception:
        print("  Not a git repository or git not available")
        return

    for commit in commits:
        diff = subprocess.run(
            ["git", "-C", repo_path, "show", commit],
            capture_output=True, text=True, errors='ignore').stdout
        for line_num, line in enumerate(diff.splitlines(), 1):
            if not line.startswith('+'):
                continue  # only inspect added lines
            for name, pattern, severity in SECRET_PATTERNS:
                m = re.search(pattern, line)
                if m and not is_placeholder(line):
                    add_finding(f"{commit[:8]} (git history)", line_num,
                                m.group(0), name, severity, "git-history")


def print_report():
    print("\n" + "=" * 55)
    print("  SECRETS SCAN RESULTS")
    print("=" * 55)
    if not findings:
        print("  No secrets detected.")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings.values(), key=lambda x: order.get(x["severity"], 4)):
        methods = "+".join(sorted(f["methods"]))
        print(f"\n  [{f['severity']}] {f['type']} ({methods})")
        print(f"    Location: {f['file']}:{f['line']}")
        print(f"    Secret:   {f['content']}")
    print(f"\n  Total unique findings: {len(findings)}")


def save_json():
    if findings:
        out = []
        for f in findings.values():
            item = dict(f)
            item["methods"] = sorted(item["methods"])
            out.append(item)
        with open("secrets.json", "w") as fp:
            json.dump(out, fp, indent=2)
        print(f"  {len(findings)} finding(s) saved to secrets.json")


print("=" * 55)
print("  SECRETS SCANNER")
print("=" * 55)
print("\n1. Scan a directory")
print("2. Scan git history")
mode = input("Pick (1 or 2): ").strip()

if mode == "2":
    repo = input("Enter git repo path: ").strip()
    scan_git_history(repo)
else:
    target = input("Enter directory to scan: ").strip()
    if os.path.isdir(target):
        scan_directory(target)
    else:
        print("Directory not found")

print_report()
save_json()
