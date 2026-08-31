# Day 13 — Mini SIEM

## What I Built

A Security Information and Event Management (SIEM) system that ingests alerts from 7 of my previous tools, normalizes them into one common schema, correlates events across tools to reconstruct attack chains, scores overall risk, and presents everything on a professional SOC dashboard with charts, a MITRE kill-chain view, an attack timeline, and a downloadable incident report.

**This is the capstone of the blue-team week — it consumes the output of the tools I built on Days 02, 06, 08, 09, 10, 11, and 12.**

---

## What is a SIEM?

A SIEM is the central brain of a security operations center. It:
1. **Ingests** logs/alerts from many security tools
2. **Normalizes** them into one consistent format
3. **Correlates** related events to detect bigger, multi-stage attacks
4. **Visualizes** everything for analysts to triage

Commercial examples: Splunk, Elastic Stack (ELK), ArcSight.

---

## How It Works

```
pip install flask
python siem.py
# Dashboard: http://127.0.0.1:5001
```

---

## Tools It Ingests (pluggable parsers)

| Day | Tool | Event type | Feeds |
|-----|------|-----------|-------|
| 02 | Port Scanner | `open_port` | Exposed attack surface |
| 06 | Traffic Analyzer | `suspicious_dns` | Malicious DNS lookups |
| 08 | CIS Auditor | `misconfiguration` | Hardening gaps |
| 09 | SSH Detector | `brute_force` | Login attacks + breaches |
| 10 | Persistence Scanner | `persistence` | Backdoors |
| 11 | Secrets Scanner | `leaked_secret` | Exposed credentials |
| 12 | Canary | `honeytoken_hit` | Deception triggers |

Each tool has a **parser** (like a real SIEM connector) that converts its native format into the common schema.

---

## The Common Schema (ECS-inspired)

Every event, regardless of source, is normalized to:
```json
{
  "timestamp": "...",
  "source_tool": "ssh-detector",
  "event_type": "brute_force",
  "severity": "CRITICAL",
  "source_ip": "185.220.101.45",
  "mitre": "T1110 Brute Force",
  "message": "8 failed SSH logins BREACH"
}
```

`source_ip` is the **correlation key** — the field that links events across different tools.

---

## The Killer Feature: Correlation

Individually, each alert is one data point. Correlated, they tell a story.

**Real example from the sample data — IP `185.220.101.45`:**
1. SSH Detector: brute-forced SSH and got in (BREACH)
2. Canary: touched a fake AWS credential (hunting for more)
3. Persistence Scanner: planted a reverse-shell systemd service

The SIEM sees the same IP across 3 tools and concludes: **"TARGETED ATTACK — this is not random scanning."** No single tool could see that. This is the entire value of a SIEM.

---

## Features

### Risk Scoring
Weighted sum of event severities + bonus for correlated incidents → a 0–100 score and posture (HEALTHY / ELEVATED / AT RISK / CRITICAL).

### Auto-Generated Analyst Conclusions
Data-driven statements like "CONFIRMED BREACH", "TARGETED ATTACK across 3 tools", "EXPOSURE: live credential in source code".

### MITRE ATT&CK Kill Chain
Groups events into attack phases (Recon → Initial Access → Credential Access → Persistence) to show the attacker's progression.

### Attack Timeline
A chronological chart showing events unfold over time.

### Correlated Incidents
Reconstructed attack chains, grouped by source IP appearing across multiple tools.

### Incident Report Export
Downloadable text report answering: What happened? When? Which host/IP? What's the evidence? — the exact incident-response questions.

### SOC Dashboard
Professional layout (sidebar nav, sticky top bar, KPI cards, Chart.js graphs) following Splunk/Kibana design principles: critical info top-left, KPI cards up top, consistent color semantics.

---

## What I Learned

- **SIEM architecture** — ingest → normalize → correlate → visualize
- **Log normalization** — converting many formats into one schema (like Elastic Common Schema)
- **Event correlation** — linking events by shared fields to detect multi-stage attacks
- **The key SIEM insight** — single events are noise; correlated events are intelligence
- **Risk scoring** — quantifying security posture from event data
- **MITRE ATT&CK kill chain** — mapping events to attacker progression
- **Data visualization** — Chart.js dashboards, timeline charts
- **SOC dashboard UX** — designing for analysts, not just aesthetics
- **Incident reporting** — turning raw events into an actionable narrative

---

## Future: Real-Time Pipeline

Currently reads JSON files. To make it live:
1. Add a `POST /ingest` endpoint; tools push events instead of writing files
2. Store in SQLite for persistent history
3. WebSockets for live dashboard updates (no refresh)
4. Run each tool continuously (systemd services / schedulers)
5. Docker Compose to spin up the whole stack

That would turn 13 separate scripts into one live security platform.

---

## Frameworks Referenced

| Framework | Relevance |
|-----------|-----------|
| **MITRE ATT&CK** | Kill-chain phases and technique tagging |
| **Elastic Common Schema** | Event normalization model |
| **NIST 800-61** | Incident response / reporting |

---

## Project Structure

```
mini-siem/
├── siem.py              # Ingestion + normalization + correlation + dashboard
├── sample_data/         # Sample alert files from days 02/06/08/09/10/11/12
│   ├── ssh_alerts.json
│   ├── persistence_findings.json
│   ├── canary_tokens.json
│   ├── cis_findings.json
│   ├── secrets_findings.json
│   ├── port_scan.json
│   └── network_dns.json
└── README.md            # This file
```

---

**#30DaysOfCyber**
