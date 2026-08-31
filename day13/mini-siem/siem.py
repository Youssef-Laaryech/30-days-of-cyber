import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from flask import Flask, render_template_string, request

app = Flask(__name__)
DATA_DIR = "sample_data"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_json(name):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except json.JSONDecodeError:
        return []


# ---------- Parsers: each converts one tool's format into the common schema ----------
# Common schema: timestamp, source_tool, event_type, severity, source_ip, mitre, message

def make_event(tool, etype, severity, message, source_ip=None, mitre="", ts=None):
    return {
        "timestamp": ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_tool": tool,
        "event_type": etype,
        "severity": severity,
        "source_ip": source_ip,
        "mitre": mitre,
        "message": message,
    }


def parse_ssh():
    events = []
    times = ["2026-08-31 22:40:00", "2026-08-31 22:44:00"]
    for i, a in enumerate(load_json("ssh_alerts.json")):
        breach = " BREACH" if a.get("login_succeeded") else ""
        msg = f"{a['failed_attempts']} failed SSH logins{breach} (users: {', '.join(a['usernames_tried'])})"
        ts = times[i] if i < len(times) else None
        events.append(make_event("ssh-detector", "brute_force", a["severity"], msg,
                                  a["source_ip"], ", ".join(a.get("mitre_techniques", [])), ts))
    return events


def parse_persistence():
    events = []
    for f in load_json("persistence_findings.json"):
        # try to extract an IP from the malicious command line
        ip = None
        import re
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', f.get("line", ""))
        if m:
            ip = m.group(1)
        msg = f"{f['reason']} in {f['location']}"
        events.append(make_event("persistence-scanner", "persistence", f["severity"], msg,
                                  ip, f.get("mitre", "")))
    return events


def parse_canary():
    events = []
    for t in load_json("canary_tokens.json"):
        for trig in t.get("triggers", []):
            msg = f"Honeytoken '{t['type']}' touched ({t['memo']})"
            events.append(make_event("canary", "honeytoken_hit", "HIGH", msg,
                                      trig.get("source_ip"), t.get("mitre_engage", ""),
                                      trig.get("time")))
    return events


def parse_cis():
    events = []
    for c in load_json("cis_findings.json"):
        if c["status"] in ("FAIL", "WARN"):
            msg = f"{c['status']}: {c['check']}"
            events.append(make_event("cis-auditor", "misconfiguration", c["severity"], msg,
                                     None, c.get("cis_ref", ""), "2026-08-31 22:30:00"))
    return events


def parse_secrets():
    events = []
    for s in load_json("secrets_findings.json"):
        msg = f"{s['type']} in {s['file']}:{s['line']}"
        events.append(make_event("secrets-scanner", "leaked_secret", s["severity"], msg,
                                 None, "T1552 Unsecured Credentials"))
    return events


def parse_ports():
    events = []
    risky = {3389: "RDP exposed", 445: "SMB exposed", 23: "Telnet exposed"}
    for p in load_json("port_scan.json"):
        sev = "MEDIUM" if p["port"] in risky else "INFO"
        msg = f"Open port {p['port']} ({p['service']}) on {p['target']}"
        events.append(make_event("port-scanner", "open_port", sev, msg, p["target"]))
    return events


def parse_network():
    events = []
    suspicious = ["malware", "c2", ".ru", "beacon"]
    for d in load_json("network_dns.json"):
        q = d["dns_query"].lower()
        if any(s in q for s in suspicious):
            msg = f"Suspicious DNS query: {d['dns_query']}"
            events.append(make_event("traffic-analyzer", "suspicious_dns", "HIGH", msg,
                                     d.get("source_ip"), "T1071.004 DNS"))
    return events


PARSERS = [parse_ssh, parse_persistence, parse_canary, parse_cis,
           parse_secrets, parse_ports, parse_network]


def ingest_all():
    events = []
    for parser in PARSERS:
        events.extend(parser())
    events.sort(key=lambda e: SEV_ORDER.get(e["severity"], 5))
    return events


def correlate(events):
    """Find IPs appearing across multiple tools = multi-stage targeted attack."""
    by_ip = defaultdict(list)
    for e in events:
        if e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    incidents = []
    for ip, evs in by_ip.items():
        tools = set(e["source_tool"] for e in evs)
        if len(tools) >= 2:
            incidents.append({
                "source_ip": ip,
                "tools": sorted(tools),
                "event_count": len(evs),
                "severity": "CRITICAL",
                "story": [f"{e['source_tool']}: {e['message']}" for e in evs]
            })
    return incidents


# ---------- Analytics: data-driven risk scoring and conclusions ----------

SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def analyze(events, incidents):
    """Produce a risk score and human-readable conclusions from the events."""
    # Risk score = weighted sum of severities + big bonus for correlated incidents
    score = sum(SEV_WEIGHT.get(e["severity"], 0) for e in events)
    score += len(incidents) * 25
    score = min(score, 100)

    if score >= 70:
        posture = "CRITICAL"
    elif score >= 40:
        posture = "AT RISK"
    elif score >= 15:
        posture = "ELEVATED"
    else:
        posture = "HEALTHY"

    # Top attacker IPs by event volume
    ip_counts = Counter(e["source_ip"] for e in events if e["source_ip"])
    top_ips = ip_counts.most_common(5)

    # Auto-generated conclusions
    conclusions = []
    breach_ips = [e["source_ip"] for e in events
                  if e["event_type"] == "brute_force" and "BREACH" in e["message"]]
    for ip in set(breach_ips):
        conclusions.append(f"CONFIRMED BREACH: {ip} successfully brute-forced SSH access.")

    for inc in incidents:
        conclusions.append(
            f"TARGETED ATTACK: {inc['source_ip']} appears across {len(inc['tools'])} "
            f"tools ({', '.join(inc['tools'])}) — this is not random scanning.")

    if any(e["event_type"] == "leaked_secret" and e["severity"] == "CRITICAL" for e in events):
        conclusions.append("EXPOSURE: A live credential was found in source code — rotate immediately.")

    misconfigs = [e for e in events if e["event_type"] == "misconfiguration"]
    if misconfigs:
        conclusions.append(
            f"HARDENING GAP: {len(misconfigs)} misconfiguration(s) detected that weaken defenses.")

    if not conclusions:
        conclusions.append("No high-confidence conclusions. Environment appears stable.")

    return {
        "score": score,
        "posture": posture,
        "top_ips": top_ips,
        "conclusions": conclusions,
    }


# ---------- MITRE ATT&CK kill-chain mapping ----------

# Maps each event type to a kill-chain phase (ordered)
KILL_CHAIN = [
    ("Reconnaissance", ["open_port", "suspicious_dns"]),
    ("Initial Access", ["brute_force"]),
    ("Credential Access", ["leaked_secret", "honeytoken_hit"]),
    ("Persistence", ["persistence"]),
    ("Weakness / Misconfig", ["misconfiguration"]),
]


def kill_chain(events):
    """Group events into kill-chain phases to show attacker progression."""
    phases = []
    for phase_name, types in KILL_CHAIN:
        matched = [e for e in events if e["event_type"] in types]
        phases.append({
            "phase": phase_name,
            "count": len(matched),
            "events": matched,
            "active": len(matched) > 0
        })
    return phases


def build_timeline(events):
    """Return events that have timestamps, sorted chronologically."""
    timed = [e for e in events if e.get("timestamp")]
    timed.sort(key=lambda e: e["timestamp"])
    return timed


def build_report(events, incidents, analysis):
    """Generate a plain-text incident report answering the key IR questions."""
    lines = []
    lines.append("=" * 60)
    lines.append("  INCIDENT REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"SECURITY POSTURE: {analysis['posture']} (risk score {analysis['score']}/100)")
    lines.append(f"TOTAL EVENTS: {len(events)}")
    lines.append("")

    lines.append("--- WHAT HAPPENED ---")
    for c in analysis["conclusions"]:
        lines.append(f"  * {c}")
    lines.append("")

    if incidents:
        lines.append("--- CORRELATED INCIDENTS (attack chains) ---")
        for inc in incidents:
            lines.append(f"  IP {inc['source_ip']} — active across {', '.join(inc['tools'])}")
            for s in inc["story"]:
                lines.append(f"      -> {s}")
        lines.append("")

    lines.append("--- TIMELINE ---")
    for e in build_timeline(events):
        ip = e["source_ip"] or "-"
        lines.append(f"  {e['timestamp']}  [{e['severity']}] {e['source_tool']}  {ip}  {e['message']}")
    lines.append("")

    lines.append("--- TOP SOURCE IPs ---")
    for ip, count in analysis["top_ips"]:
        lines.append(f"  {ip}: {count} events")
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Mini SIEM</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:#0a0e14; color:#c9d1d9; font-family:'Segoe UI',Arial,sans-serif; }
    a { color:#58a6ff; text-decoration:none; } a:hover { text-decoration:underline; }

    /* Layout: fixed sidebar + main content */
    .sidebar { position:fixed; top:0; left:0; width:210px; height:100vh; background:#0d1117;
               border-right:1px solid #21262d; padding:20px 0; }
    .sidebar .logo { color:#58a6ff; font-size:20px; font-weight:800; padding:0 20px 20px; letter-spacing:1px; }
    .sidebar .navitem { display:block; padding:11px 20px; color:#8b949e; font-size:14px; border-left:3px solid transparent; }
    .sidebar .navitem:hover { background:#161b22; color:#c9d1d9; border-left-color:#58a6ff; text-decoration:none; }
    .sidebar .section-label { color:#484f58; font-size:10px; text-transform:uppercase; letter-spacing:1px; padding:16px 20px 6px; }
    .main { margin-left:210px; padding:0 0 40px; }

    /* Sticky top bar */
    .topbar { position:sticky; top:0; z-index:10; background:#0d1117; border-bottom:1px solid #21262d;
              padding:14px 28px; display:flex; justify-content:space-between; align-items:center; }
    .topbar .title { font-size:18px; font-weight:700; }
    .topbar .meta { color:#6e7681; font-size:12px; }

    .content { padding:24px 28px; }
    h2 { color:#8b949e; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin:28px 0 12px; }

    /* KPI cards */
    .kpis { display:grid; grid-template-columns:repeat(6,1fr); gap:14px; }
    .kpi { background:#0d1117; border:1px solid #21262d; border-radius:10px; padding:16px; text-align:center; }
    .kpi .num { font-size:30px; font-weight:800; line-height:1.1; }
    .kpi .lbl { color:#6e7681; font-size:11px; text-transform:uppercase; letter-spacing:.5px; margin-top:6px; }
    .kpi.alert { border-color:#f85149; }

    .grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; }
    .panel { background:#0d1117; border:1px solid #21262d; border-radius:10px; padding:18px; }
    .panel h3 { font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:.5px; margin-bottom:12px; }
    canvas { max-height:220px; }

    .CRITICAL { color:#f85149; } .HIGH { color:#ff9f1c; } .MEDIUM { color:#e3b341; }
    .LOW { color:#3fb950; } .INFO { color:#6e7681; }
    .ATRISK { color:#ff9f1c; } .HEALTHY { color:#3fb950; } .ELEVATED { color:#e3b341; }
    .muted { color:#6e7681; font-size:12px; }

    table { width:100%; border-collapse:collapse; background:#0d1117; border:1px solid #21262d; border-radius:10px; overflow:hidden; }
    th,td { text-align:left; padding:9px 12px; border-bottom:1px solid #21262d; font-size:13px; }
    th { color:#8b949e; text-transform:uppercase; font-size:10px; letter-spacing:.5px; background:#161b22; }
    tr:last-child td { border-bottom:none; }

    .incident { background:#160f11; border-left:4px solid #f85149; border-radius:8px; padding:14px 18px; margin-bottom:12px; }
    .incident h3 { color:#f85149; font-size:15px; margin-bottom:6px; }
    .step { margin-left:14px; font-size:13px; padding:2px 0; color:#c9d1d9; }
    .concl { padding:10px 14px; border-left:3px solid #58a6ff; background:#0d1420; margin-bottom:8px; font-size:14px; border-radius:0 6px 6px 0; }

    .kc { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; }
    .kc .phase { background:#0d1117; border:1px solid #21262d; border-radius:10px; padding:14px; }
    .kc .phase.active { border-color:#f85149; }
    .kc .phase.inactive { opacity:.45; }
    .btn { background:#1f6feb; color:#fff; padding:7px 14px; border-radius:6px; font-size:13px; }
    .btn:hover { background:#388bfd; text-decoration:none; }
    .bar { height:8px; border-radius:4px; background:#21262d; overflow:hidden; margin-top:6px; }
    .bar > div { height:100%; background:#f85149; }
  </style>
</head>
<body>
  <div class="sidebar">
    <div class="logo">MINI SIEM</div>
    <div class="section-label">Overview</div>
    <a class="navitem" href="#top">Dashboard</a>
    <a class="navitem" href="#conclusions">Conclusions</a>
    <div class="section-label">Analysis</div>
    <a class="navitem" href="#killchain">Kill Chain</a>
    <a class="navitem" href="#timeline">Timeline</a>
    <a class="navitem" href="#incidents">Incidents</a>
    <div class="section-label">Data</div>
    <a class="navitem" href="#ips">Top IPs</a>
    <a class="navitem" href="#feed">Event Feed</a>
    <div class="section-label">Export</div>
    <a class="navitem" href="/report">Incident Report</a>
  </div>

  <div class="main">
    <div class="topbar" id="top">
      <div class="title">Security Operations Dashboard</div>
      <div class="meta">{{ tool_count }} tools · {{ total }} events · {{ now }}</div>
    </div>

    <div class="content">
      <!-- KPI row -->
      <div class="kpis">
        <div class="kpi {{ 'alert' if analysis.score >= 40 else '' }}">
          <div class="num {{ analysis.posture|replace(' ','') }}">{{ analysis.score }}</div>
          <div class="lbl">Risk Score</div>
        </div>
        <div class="kpi">
          <div class="num {{ analysis.posture|replace(' ','') }}" style="font-size:20px;">{{ analysis.posture }}</div>
          <div class="lbl">Posture</div>
        </div>
        <div class="kpi"><div class="num">{{ total }}</div><div class="lbl">Events</div></div>
        <div class="kpi"><div class="num CRITICAL">{{ sev.CRITICAL }}</div><div class="lbl">Critical</div></div>
        <div class="kpi"><div class="num HIGH">{{ sev.HIGH }}</div><div class="lbl">High</div></div>
        <div class="kpi {{ 'alert' if incidents else '' }}"><div class="num CRITICAL">{{ incidents|length }}</div><div class="lbl">Correlated</div></div>
      </div>

      <!-- Charts -->
      <h2>Analytics</h2>
      <div class="grid3">
        <div class="panel"><h3>Severity Distribution</h3><canvas id="sevChart"></canvas></div>
        <div class="panel"><h3>Events per Tool</h3><canvas id="toolChart"></canvas></div>
        <div class="panel"><h3>Event Types</h3><canvas id="typeChart"></canvas></div>
      </div>

      <!-- Conclusions -->
      <h2 id="conclusions">Analyst Conclusions <a class="btn" href="/report" style="float:right;">Download Report</a></h2>
      {% for c in analysis.conclusions %}<div class="concl">{{ c }}</div>{% endfor %}

      <!-- Kill chain -->
      <h2 id="killchain">MITRE ATT&CK Kill Chain</h2>
      <div class="kc">
        {% for p in phases %}
        <div class="phase {{ 'active' if p.active else 'inactive' }}">
          <div class="muted">{{ loop.index }}. {{ p.phase }}</div>
          <div class="num {{ 'CRITICAL' if p.active else 'INFO' }}" style="font-size:26px;font-weight:800;">{{ p.count }}</div>
          {% for e in p.events %}<div class="muted" style="font-size:11px;">{{ e.source_ip or '' }} {{ e.event_type }}</div>{% endfor %}
        </div>
        {% endfor %}
      </div>

      <!-- Timeline -->
      <h2 id="timeline">Attack Timeline</h2>
      <div class="panel"><canvas id="timelineChart"></canvas></div>

      <!-- Incidents -->
      <h2 id="incidents">Correlated Incidents</h2>
      {% if incidents %}
        {% for inc in incidents %}
        <div class="incident">
          <h3>CRITICAL — {{ inc.source_ip }} active across {{ inc.tools|length }} tools</h3>
          <div class="muted">Tools: {{ inc.tools|join(', ') }} | {{ inc.event_count }} events</div>
          <div style="margin-top:8px;">Attack chain:</div>
          {% for s in inc.story %}<div class="step">&rarr; {{ s }}</div>{% endfor %}
        </div>
        {% endfor %}
      {% else %}<div class="muted">No cross-tool correlations found.</div>{% endif %}

      <!-- Top IPs -->
      <h2 id="ips">Top Source IPs</h2>
      <table>
        <tr><th>IP</th><th>Events</th><th>Volume</th></tr>
        {% for ip, count in analysis.top_ips %}
        <tr><td>{{ ip }}</td><td>{{ count }}</td>
          <td style="width:40%"><div class="bar"><div style="width:{{ (count / analysis.top_ips[0][1] * 100)|int }}%;"></div></div></td>
        </tr>{% endfor %}
      </table>

      <!-- Event feed -->
      <h2 id="feed">Event Feed &nbsp;<span class="muted">
        <a href="/">all</a> · <a href="/?sev=CRITICAL">critical</a> ·
        <a href="/?sev=HIGH">high</a> · <a href="/?sev=MEDIUM">medium</a> · <a href="/?sev=LOW">low</a>
      </span></h2>
      <table>
        <tr><th>Time</th><th>Tool</th><th>Type</th><th>Sev</th><th>Source IP</th><th>Message</th><th>MITRE</th></tr>
        {% for e in events %}
        <tr>
          <td class="muted">{{ e.timestamp }}</td>
          <td>{{ e.source_tool }}</td>
          <td>{{ e.event_type }}</td>
          <td class="{{ e.severity }}">{{ e.severity }}</td>
          <td>{{ e.source_ip or '-' }}</td>
          <td>{{ e.message }}</td>
          <td class="muted">{{ e.mitre }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

<script>
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#21262d';
new Chart(document.getElementById('sevChart'), {
  type:'doughnut',
  data:{ labels:{{ sev_labels|safe }}, datasets:[{ data:{{ sev_values|safe }},
    backgroundColor:['#f85149','#ff9f1c','#e3b341','#3fb950','#6e7681'] }] },
  options:{ plugins:{ legend:{ position:'bottom' } } }
});
new Chart(document.getElementById('toolChart'), {
  type:'bar',
  data:{ labels:{{ tool_labels|safe }}, datasets:[{ label:'events', data:{{ tool_values|safe }},
    backgroundColor:'#58a6ff' }] },
  options:{ plugins:{ legend:{ display:false } }, scales:{ x:{ ticks:{ font:{ size:9 } } } } }
});
new Chart(document.getElementById('typeChart'), {
  type:'bar', 
  data:{ labels:{{ type_labels|safe }}, datasets:[{ label:'count', data:{{ type_values|safe }},
    backgroundColor:'#a371f7' }] },
  options:{ indexAxis:'y', plugins:{ legend:{ display:false } } }
});
const tlSevColor = {CRITICAL:'#f85149',HIGH:'#ff9f1c',MEDIUM:'#e3b341',LOW:'#3fb950',INFO:'#6e7681'};
new Chart(document.getElementById('timelineChart'), {
  type:'scatter',
  data:{ datasets:[{
    label:'events',
    data:{{ timeline_points|safe }},
    pointRadius:8, pointHoverRadius:11,
    backgroundColor:{{ timeline_colors|safe }}
  }] },
  options:{
    plugins:{ legend:{ display:false },
      tooltip:{ callbacks:{ label:(c)=> {{ timeline_labels|safe }}[c.dataIndex] } } },
    scales:{
      x:{ type:'category', labels:{{ timeline_times|safe }}, ticks:{ font:{ size:10 } } },
      y:{ display:false, min:-1, max:1 }
    }
  }
});
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    events = ingest_all()
    incidents = correlate(events)
    analysis = analyze(events, incidents)
    phases = kill_chain(events)
    timeline = build_timeline(events)

    sev_filter = request.args.get("sev")
    shown = [e for e in events if e["severity"] == sev_filter] if sev_filter else events

    sev_counts = Counter(e["severity"] for e in events)
    tool_counts = Counter(e["source_tool"] for e in events)
    type_counts = Counter(e["event_type"] for e in events)

    # timeline chart data (x = index along time axis, y = 0)
    tl_colors = {"CRITICAL": "#f85149", "HIGH": "#ff9f1c", "MEDIUM": "#e3b341",
                 "LOW": "#3fb950", "INFO": "#6e7681"}
    timeline_points = [{"x": i, "y": 0} for i in range(len(timeline))]
    timeline_colors = [tl_colors.get(e["severity"], "#6e7681") for e in timeline]
    timeline_times = [e["timestamp"][11:] for e in timeline]  # HH:MM:SS
    timeline_labels = [f"{e['source_tool']}: {e['message'][:40]}" for e in timeline]

    return render_template_string(
        DASHBOARD_HTML,
        events=shown,
        incidents=incidents,
        analysis=analysis,
        phases=phases,
        total=len(events),
        sev={k: sev_counts.get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        tool_count=len(tool_counts),
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        sev_labels=json.dumps(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
        sev_values=json.dumps([sev_counts.get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]]),
        tool_labels=json.dumps(list(tool_counts.keys())),
        tool_values=json.dumps(list(tool_counts.values())),
        type_labels=json.dumps(list(type_counts.keys())),
        type_values=json.dumps(list(type_counts.values())),
        timeline_points=json.dumps(timeline_points),
        timeline_colors=json.dumps(timeline_colors),
        timeline_times=json.dumps(timeline_times),
        timeline_labels=json.dumps(timeline_labels),
    )


@app.route("/report")
def report():
    events = ingest_all()
    incidents = correlate(events)
    analysis = analyze(events, incidents)
    text = build_report(events, incidents, analysis)
    return app.response_class(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=incident_report.txt"}
    )


if __name__ == "__main__":
    print("=" * 55)
    print("  MINI SIEM")
    print("  Dashboard: http://127.0.0.1:5001")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5001)
