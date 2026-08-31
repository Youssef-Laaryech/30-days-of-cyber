import json
import os
from datetime import datetime
from flask import Flask, request, Response, render_template_string

TOKENS_FILE = "tokens.json"
app = Flask(__name__)

# A 1x1 transparent GIF used as the web-bug pixel response
PIXEL_GIF = bytes([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B
])


def load_tokens():
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE) as f:
                content = f.read().strip()
                return json.loads(content) if content else []
        except json.JSONDecodeError:
            return []
    return []


def save_tokens(tokens):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)


def fire_token(token_id):
    tokens = load_tokens()
    for token in tokens:
        if token["id"] == token_id:
            event = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", "unknown"),
                "path": request.path
            }
            token["triggered"] = True
            token["triggers"].append(event)
            save_tokens(tokens)
            print("\n" + "!" * 55)
            print("  *** CANARY TRIGGERED ***")
            print(f"    Token:  {token['id']} ({token['type']})  Memo: {token['memo']}")
            print(f"    Source: {event['source_ip']}  Time: {event['time']}")
            print("!" * 55 + "\n")
            return token
    return None


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Canary SOC Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body { background:#0d1117; color:#c9d1d9; font-family: 'Courier New', monospace; padding:20px; }
    h1 { color:#58a6ff; }
    .stats { display:flex; gap:20px; margin-bottom:20px; }
    .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:15px 25px; }
    .card .num { font-size:32px; font-weight:bold; }
    .armed { color:#3fb950; }
    .fired { color:#f85149; }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th, td { text-align:left; padding:8px 12px; border-bottom:1px solid #30363d; font-size:14px; }
    th { color:#8b949e; }
    .badge-armed { color:#3fb950; }
    .badge-fired { color:#f85149; font-weight:bold; }
    .trigger-row { background:#2d1418; }
    .muted { color:#6e7681; font-size:12px; }
  </style>
</head>
<body>
  <h1>Canary SOC Dashboard</h1>
  <div class="muted">Auto-refreshes every 3s | {{ now }}</div>
  <div class="stats">
    <div class="card"><div class="num">{{ total }}</div>Total Tokens</div>
    <div class="card"><div class="num armed">{{ armed }}</div>Armed</div>
    <div class="card"><div class="num fired">{{ fired }}</div>Triggered</div>
    <div class="card"><div class="num fired">{{ events }}</div>Total Alerts</div>
  </div>

  <h2>Tokens</h2>
  <table>
    <tr><th>Status</th><th>ID</th><th>Type</th><th>Memo</th><th>MITRE Engage</th><th>Triggers</th></tr>
    {% for t in tokens %}
    <tr>
      <td class="{{ 'badge-fired' if t.triggered else 'badge-armed' }}">
        {{ 'TRIGGERED' if t.triggered else 'armed' }}
      </td>
      <td>{{ t.id }}</td>
      <td>{{ t.type }}</td>
      <td>{{ t.memo }}</td>
      <td class="muted">{{ t.mitre_engage }}</td>
      <td>{{ t.triggers|length }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Alert Feed</h2>
  <table>
    <tr><th>Time</th><th>Token</th><th>Type</th><th>Source IP</th><th>User-Agent</th></tr>
    {% for a in alerts %}
    <tr class="trigger-row">
      <td>{{ a.time }}</td>
      <td>{{ a.token_id }}</td>
      <td>{{ a.type }}</td>
      <td>{{ a.source_ip }}</td>
      <td class="muted">{{ a.user_agent[:50] }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.route("/")
def dashboard():
    tokens = load_tokens()
    # build a flat, newest-first list of all trigger events
    alerts = []
    for t in tokens:
        for ev in t["triggers"]:
            alerts.append({
                "time": ev["time"],
                "token_id": t["id"],
                "type": t["type"],
                "source_ip": ev["source_ip"],
                "user_agent": ev.get("user_agent", "")
            })
    alerts.sort(key=lambda x: x["time"], reverse=True)

    return render_template_string(
        DASHBOARD_HTML,
        tokens=tokens,
        alerts=alerts,
        total=len(tokens),
        armed=sum(1 for t in tokens if not t["triggered"]),
        fired=sum(1 for t in tokens if t["triggered"]),
        events=len(alerts),
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/c/<token_id>", methods=["GET", "POST"])
@app.route("/c/<token_id>/<path:extra>", methods=["GET", "POST"])
def trigger(token_id, extra=None):
    token = fire_token(token_id)
    if token is None:
        return Response("Not found", status=404)
    if extra and ("pixel" in extra or extra.endswith(".gif")):
        return Response(PIXEL_GIF, mimetype="image/gif")
    return Response("OK", status=200)


if __name__ == "__main__":
    print("=" * 55)
    print("  CANARY ALERT SERVER + SOC DASHBOARD")
    print("  Dashboard: http://127.0.0.1:5000")
    print("  Triggers:  http://127.0.0.1:5000/c/<token_id>")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5000)
