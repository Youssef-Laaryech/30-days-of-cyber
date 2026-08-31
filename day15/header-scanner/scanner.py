import requests
import re
import json

# Security headers to grade. validate() returns True if the value is strong.
RULES = [
    {
        "header": "Strict-Transport-Security",
        "severity": "HIGH", "points": 30,
        "stops": "SSL stripping (HTTPS downgrade)",
        "validate": lambda v: bool(re.search(r"max-age=\s*([1-9]\d*)", v)),
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "header": "Content-Security-Policy",
        "severity": "HIGH", "points": 30,
        "stops": "Cross-site scripting (XSS)",
        # only flag unsafe-inline when it can affect scripts
        "validate": lambda v: not ("'unsafe-inline'" in v and
                                   re.search(r"(script-src|default-src)[^;]*'unsafe-inline'", v)),
        "fix": "Content-Security-Policy without 'unsafe-inline' in script-src",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "MEDIUM", "points": 15,
        "stops": "MIME sniffing",
        "validate": lambda v: v.strip().lower() == "nosniff",
        "fix": "X-Content-Type-Options: nosniff",
    },
    {
        "header": "X-Frame-Options",
        "severity": "MEDIUM", "points": 15,
        "stops": "Clickjacking",
        "validate": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
        "fix": "X-Frame-Options: DENY",
    },
    {
        "header": "Referrer-Policy",
        "severity": "LOW", "points": 5,
        "stops": "Referer URL leakage",
        "validate": lambda v: v.strip() != "",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "severity": "LOW", "points": 5,
        "stops": "Camera/mic/geolocation abuse",
        "validate": lambda v: v.strip() != "",
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
]

# Headers that leak software info to attackers (should be removed/hidden)
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def grade(score):
    for cutoff, letter in [(90, "A"), (80, "B"), (70, "C"), (60, "D")]:
        if score >= cutoff:
            return letter
    return "F"


def scan(url):
    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None

    headers = resp.headers
    total_points = sum(r["points"] for r in RULES)
    earned = 0
    findings = []
    remediations = []

    print(f"\nScanning {url}   (status {resp.status_code})")
    print("=" * 55)

    for rule in RULES:
        name = rule["header"]
        if name in headers:
            value = headers[name]
            if rule["validate"](value):
                earned += rule["points"]
                status = "OK"
                print(f"  [OK]      {name} ({rule['severity']})")
            else:
                earned += rule["points"] // 2
                status = "WEAK"
                print(f"  [WEAK]    {name} = {value[:40]}")
                remediations.append(rule["fix"])
        else:
            status = "MISSING"
            print(f"  [MISSING] {name} ({rule['severity']}) - stops {rule['stops']}")
            remediations.append(rule["fix"])
        findings.append({"header": name, "status": status, "severity": rule["severity"]})

    # Info-leak check
    leaks = []
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            leaks.append({"header": h, "value": headers[h]})
            print(f"  [LEAK]    {h}: {headers[h]}  (reveals software to attackers)")

    score = round((earned / total_points) * 100)
    letter = grade(score)
    print("=" * 55)
    print(f"  SCORE: {score}/100   GRADE: {letter}")

    if remediations:
        print("\n  Remediation:")
        for fix in remediations:
            print(f"    - {fix}")
    for leak in leaks:
        print(f"    - Remove/obfuscate the {leak['header']} header")

    return {
        "url": url,
        "status_code": resp.status_code,
        "score": score,
        "grade": letter,
        "findings": findings,
        "info_leaks": leaks,
    }


print("=" * 55)
print("  HTTP SECURITY HEADER SCANNER")
print("=" * 55)
print("\n1. Scan one URL")
print("2. Scan multiple URLs (comma-separated)")
choice = input("Pick (1 or 2): ").strip()

if choice == "2":
    raw = input("Enter URLs (comma-separated): ").strip()
    urls = [u.strip() for u in raw.split(",") if u.strip()]
else:
    urls = [input("Enter URL: ").strip()]

results = []
for u in urls:
    if not u.startswith("http"):
        u = "https://" + u
    r = scan(u)
    if r:
        results.append(r)

# Comparison table for multiple URLs
if len(results) > 1:
    print("\n" + "=" * 55)
    print("  COMPARISON")
    print("=" * 55)
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        print(f"  {r['grade']}  {r['score']:>3}/100   {r['url']}")

# JSON export
if results:
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to scan_results.json")
