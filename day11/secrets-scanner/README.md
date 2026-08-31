# Day 11 — Secrets Scanner

## What I Built

A secrets scanner that hunts codebases and git history for leaked credentials — API keys, tokens, passwords, private keys — using two detection methods (regex patterns + Shannon entropy), with deduplication, severity scoring, secret redaction, and JSON export.

---

## How It Works

```
python scanner.py
```

Choose:
1. **Scan a directory** — recursively scan files for secrets
2. **Scan git history** — check every commit for secrets that were committed (even if later deleted)

Example output:
```
  [CRITICAL] AWS Access Key (pattern)
    Location: testdata/config.py:4
    Secret:   AKIA************2XYZ

  [CRITICAL] GitHub Token (entropy+pattern)
    Location: testdata/config.py:5
    Secret:   ghp_********************************2qWq

  [LOW] High-entropy string (entropy)
    Location: testdata/config.py:12
    Secret:   xQ9m************************D0sA

  Total unique findings: 7
```

---

## Why This Matters

Developers accidentally commit secrets into code. When that code hits GitHub, attackers scan for the leaked keys and use them within minutes. Leaked secrets are one of the most common causes of real breaches. This tool finds them before they cause damage.

**MITRE ATT&CK:** T1552 — Unsecured Credentials.

---

## The Two Detection Methods

### 1. Pattern Matching (regex)
Known secrets have recognizable formats:
- AWS keys start with `AKIA`
- GitHub tokens start with `ghp_`
- Stripe keys start with `sk_live_`
- Slack tokens start with `xoxb-`

**Precise, low false positives, but only catches known formats.**

### 2. Shannon Entropy
Entropy measures randomness (bits per character):
- `"aaaaaaaa"` → entropy ≈ 0 (predictable)
- `"password"` → entropy ≈ 2.75 (low, dictionary word)
- `"xQ9mK2pL7vB4nR8wT3zY"` → entropy ≈ 5.0 (high, random)

Real secrets are randomly generated → high entropy. A high-entropy string that isn't a dictionary word is probably a secret — **even one with no known pattern**.

**Broad, catches unknown secrets, but needs false-positive filtering.**

Together: patterns catch known keys, entropy catches everything else. This is how Gitleaks, TruffleHog, and other pro tools work.

---

## Features

### Severity Scoring
| Severity | Examples |
|----------|----------|
| CRITICAL | AWS, GitHub, Stripe, Slack, private keys |
| HIGH | Google API, JWT, DB connection strings |
| MEDIUM | Generic API key, password assignment |
| LOW | High-entropy string (no known pattern) |

### Deduplication
When both methods catch the same secret, it shows once, listing both methods (`entropy+pattern`).

### Secret Redaction
Secrets are masked in output (`AKIA****2XYZ`) so the report itself doesn't leak them.

### Git History Scanning
Scans every commit with `git log --all` + `git show`. Catches secrets that were committed then deleted — they still live in git history forever, and attackers know to look there.

### Ignore Filters
Skips `.git`, `node_modules`, `__pycache__`, binaries, and images for speed and less noise.

### False Positive Defense
Filters out placeholders (`YOUR_API_KEY`, `xxxxxxxx`, `changeme`).

---

## Connections to Previous Days

- **Day 05 (Metadata Scraper):** Same file-scanning and hashing/entropy concepts.
- **Day 08–10 (Blue team):** Consistent severity model, JSON export, and safe test-data approach.

---

## What I Learned

- **Shannon entropy** — the math of randomness and how it exposes secrets
- **Regex secret patterns** — the recognizable shapes of AWS/GitHub/Stripe/etc. keys
- **Defense in depth** — combining two detection methods for full coverage
- **False positive management** — placeholder filtering, entropy thresholds
- **Git history forensics** — secrets persist in commits even after deletion
- **Deduplication** — merging findings from multiple detectors
- **Secret redaction** — never leak the secret in your own report
- **How pro tools work** — Gitleaks, TruffleHog, GitGuardian all build on these primitives

---

## How Professional Tools Extend This

Production scanners (Gitleaks, TruffleHog, Kingfisher) add:
- **Live verification** — actually call the API to confirm a secret is still active
- **700–1,000+ detection rules**
- **SARIF output** for GitHub code scanning integration
- **Pre-commit hooks** to block secrets before they're committed
- **HIBP breach checking** via k-anonymity

*Content on tool capabilities summarized from public documentation.*

---

## Frameworks Referenced

| Framework | Relevance |
|-----------|-----------|
| **MITRE ATT&CK** | T1552 Unsecured Credentials |
| **OWASP** | Sensitive Data Exposure |

---

## Testing

```
python scanner.py  →  option 1  →  testdata
```
The `testdata/config.py` has planted secrets (real-format + high-entropy) and placeholders to verify both detection and false-positive filtering.

Git history:
```
python scanner.py  →  option 2  →  path to a git repo
```

---

## Project Structure

```
secrets-scanner/
├── scanner.py           # The scanner (regex + entropy, git history)
├── testdata/
│   └── config.py        # Mock file with planted secrets
└── README.md            # This file
```

---

**#30DaysOfCyber**
