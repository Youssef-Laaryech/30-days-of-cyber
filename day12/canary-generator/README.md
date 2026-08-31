# Day 12 — Canary Token Generator

## What I Built

A self-hosted honeytoken system: a generator that mints fake credential files and tracking tokens, a real Flask alert server that fires when an attacker touches one, and a live SOC dashboard that visualizes triggers in real time. Mapped to MITRE Engage deception techniques.

---

## What is a Canary Token?

A canary token (honeytoken) is a **fake credential or file that acts as a tripwire**. You plant it somewhere an attacker would look — a fake `passwords.docx`, a fake `.env` with juicy AWS keys, a fake `kubeconfig`. It's worthless to you, but the moment an attacker touches it, it **alerts you instantly** that someone is snooping.

Named after canaries in coal mines — the bird warned miners of danger. This is the basis of **MITRE Engage** (deception defense) and the commercial **Thinkst Canary** product.

**Why it works:**
- Attackers can't tell it's fake — a fake AWS key looks identical to a real one
- Near-zero false positives — no legitimate user ever touches a honeytoken
- Early warning — catches attackers during reconnaissance, before real damage

---

## How It Works

**Two components:**

### 1. Generator (`canary.py`)
Creates fake artifacts with a unique canary URL baked in:
```
python canary.py
```

### 2. Alert Server + Dashboard (`server.py`)
A Flask server that receives triggers and shows a live dashboard:
```
python server.py
# Dashboard: http://127.0.0.1:5000
```

When an attacker touches a token's URL, the server records the event (IP, user-agent, timestamp) and the dashboard updates live.

---

## Token Types

| Type | Artifact | Trigger | Where you'd plant it |
|------|----------|---------|----------------------|
| `envfile` | Fake `.env` with buried canary URL | Attacker uses the fake `INTERNAL_METRICS_ENDPOINT` | Repo roots, container `/app/` |
| `aws` | Fake `~/.aws/credentials` | Attacker uses the decoy endpoint | Admin laptops, CI runners |
| `kubeconfig` | Fake Kubernetes config | Attacker runs `kubectl` against the fake server | `~/.kube/config` |
| `webbug` | 1x1 tracking pixel URL | Any HTTP GET on the pixel | HTML emails, wikis |
| `docx` | Fake document with remote-image URL | Document viewer loads the remote resource | Shared drives |
| `sshkey` | Fake SSH private key | Attacker uses the provisioning callback | `~/.ssh/`, dotfiles |

---

## MITRE Engage Mapping

Deception techniques from the MITRE Engage framework:

| Token | Technique |
|-------|-----------|
| envfile | EAC0011 Lures / EAC0005 Decoy Credentials |
| aws / kubeconfig / sshkey | EAC0005 Decoy Credentials |
| webbug | EAC0011 Lures (beacon) |
| docx | EAC0021 Decoy Content |

---

## The SOC Dashboard

The server hosts a live dashboard (auto-refresh every 3s) showing:
- **Stat cards** — total tokens, armed, triggered, total alerts
- **Tokens table** — status (armed/TRIGGERED), type, memo, MITRE tag
- **Alert feed** — every trigger with timestamp, source IP, and user-agent

The user-agent is a real forensic clue: `curl/8.21.0` means an automated tool touched the token, while a browser string suggests a human clicked a link.

---

## Real-World Scenario

1. You plant canary tokens across your systems (fake `.env`, fake creds, etc.) and note where each one is.
2. An attacker breaches a machine and hunts for credentials.
3. They find your fake `.env`, grab it, and try to use one of the "secrets."
4. The moment they touch the canary URL, your server fires an alert with their IP, location, and timestamp.
5. You know within seconds: you've been breached, where, and by whom — and can respond immediately.

This is exactly how Thinkst Canary and canarytokens.org work in production.

---

## Connections to Previous Days

- **Day 09 (SSH Detector):** detects the break-in
- **Day 10 (Persistence Scanner):** finds what the attacker planted
- **Day 11 (Secrets Scanner):** finds real leaked secrets
- **Day 12 (Canary):** the deception layer — traps the attacker during recon

Together: a full detection + deception defense stack.

---

## What I Learned

- **Deception defense** — the strategy of planting traps for attackers (MITRE Engage)
- **Honeytoken design** — making fake credentials indistinguishable from real ones
- **Flask web server** — routes, request handling, capturing source IP and headers
- **Trigger mechanics** — how touching a URL fires an alert
- **Live dashboards** — auto-refreshing HTML with server-side rendering (Jinja2)
- **Forensic value of metadata** — user-agent reveals tool vs. human
- **Why deception has near-zero false positives** — nobody legitimate touches a honeytoken

---

## How Professional Tools Extend This

Production canary platforms (Thinkst Canary, canarytokens.org) add:
- Real-time notifications (Telegram, webhook, email)
- Dedup/silence windows to prevent alert fatigue
- GeoIP enrichment (attacker country/city/ISP)
- HMAC-signed webhooks, rate limiting, anti-bot
- Persistent database, high-availability hosting

*Tool capability details summarized from public documentation.*

---

## Frameworks Referenced

| Framework | Relevance |
|-----------|-----------|
| **MITRE Engage** | Deception techniques (EAC0005, EAC0011, EAC0021) |
| **MITRE ATT&CK** | Detects recon (T1552 Unsecured Credentials access attempts) |

---

## Requirements

```
pip install flask
```

---

## Testing

1. Start the server: `python server.py`
2. Open the dashboard: `http://127.0.0.1:5000`
3. Create a token: `python canary.py` → option 1
4. Trigger it: `curl.exe http://127.0.0.1:5000/c/<token_id>`
5. Watch the dashboard light up with the alert

---

## Project Structure

```
canary-generator/
├── canary.py       # Token generator (6 artifact types)
├── server.py       # Flask alert server + SOC dashboard
├── artifacts/      # Generated fake files (gitignored)
├── tokens.json     # Token registry + trigger events
└── README.md       # This file
```

---

**#30DaysOfCyber**
