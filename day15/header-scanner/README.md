# Day 15 — HTTP Security Header Scanner

## What I Built

A web security scanner that audits a website's HTTP response headers for six critical security headers, validates their values, detects information-leaking headers, scores the site A–F, and provides remediation guidance. Supports scanning multiple sites for comparison and exports results to JSON.

---

## How It Works

```
pip install requests
python scanner.py
```

Choose single-URL or multi-URL mode, enter the target(s), and get a graded report.

Example (ethglobal.com):
```
Scanning https://ethglobal.com   (status 200)
  [OK]      Strict-Transport-Security (HIGH)
  [MISSING] Content-Security-Policy (HIGH) - stops Cross-site scripting (XSS)
  [MISSING] X-Content-Type-Options (MEDIUM) - stops MIME sniffing
  [OK]      X-Frame-Options (MEDIUM)
  [LEAK]    Server: cloudflare  (reveals software to attackers)
  [LEAK]    X-Powered-By: Next.js  (reveals software to attackers)
  SCORE: 45/100   GRADE: F
```

---

## What Are Security Headers?

When a server responds to a browser, it sends HTTP headers — instructions the browser follows. **Security headers** tell the browser how to protect the user. If a site omits them, the browser falls back to permissive defaults that attackers exploit.

---

## The 6 Headers Checked

| Header | Attack it stops | Severity |
|--------|----------------|----------|
| **Strict-Transport-Security (HSTS)** | SSL stripping (forcing HTTPS→HTTP downgrade) | HIGH |
| **Content-Security-Policy (CSP)** | Cross-site scripting (XSS) | HIGH |
| **X-Content-Type-Options** | MIME sniffing (disguising scripts as images) | MEDIUM |
| **X-Frame-Options** | Clickjacking (invisible iframe overlays) | MEDIUM |
| **Referrer-Policy** | Referer URL leakage (secrets in URLs) | LOW |
| **Permissions-Policy** | Camera/mic/geolocation feature abuse | LOW |

---

## Features

### Value Validation (not just presence)
Checks the header's value is actually strong:
- HSTS must have a positive `max-age` (`max-age=0` disables it)
- CSP flagged weak only if `unsafe-inline` affects `script-src`/`default-src`
- X-Content-Type-Options must be exactly `nosniff`
- X-Frame-Options must be `DENY` or `SAMEORIGIN`

### Scoring & Grading
Weighted by severity (HIGH=30, MEDIUM=15, LOW=5) → percentage → letter grade (A–F). Mirrors Mozilla Observatory and securityheaders.com.

### Information Leak Detection
Flags headers that reveal the tech stack to attackers: `Server`, `X-Powered-By`, `X-AspNet-Version`. Knowing a site runs Next.js or a specific server version helps attackers find targeted exploits.

### Multi-URL Comparison
Scan several sites at once and get a ranked comparison table.

### JSON Export
Saves `scan_results.json` for reporting or feeding into other tools (like a SIEM).

### Remediation Guidance
Every missing/weak header comes with the exact configuration line to fix it.

---

## What I Learned

- **HTTP fundamentals** — request/response structure, status lines, headers, body
- **The 6 security headers** and the specific attack each one stops
- **SSL stripping, XSS, clickjacking, MIME sniffing** — real web attack classes
- **Value validation** — a header can be present but useless (`max-age=0`)
- **Information disclosure** — `Server`/`X-Powered-By` headers leak recon data
- **Scoring rubrics** — how security-grading tools weight and grade findings
- **`requests` library** — fetching pages and reading case-insensitive headers

---

## Real-World Context

This is a simplified version of **Mozilla Observatory** and **securityheaders.com**. Those tools do deeper CSP analysis, cookie checks, and TLS grading. For a full audit, graduate to those. This scanner teaches the core concepts they're built on.

---

## Frameworks Referenced

| Reference | Relevance |
|-----------|-----------|
| **OWASP Secure Headers Project** | Canonical list of security headers |
| **CWE-693** | Protection Mechanism Failure (missing headers) |
| **MDN Web Docs** | Authoritative header documentation |

---

## Project Structure

```
header-scanner/
├── scanner.py          # The scanner (6 headers, scoring, multi-URL, JSON)
└── README.md           # This file
```

---

**#30DaysOfCyber**
