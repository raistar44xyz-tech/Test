"""
Flask status dashboard — runs on port 5000 in a background thread.
"""
import threading
from flask import Flask, jsonify, render_template_string
import stats as stats_tracker

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Netflix Bot — Status</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d0d0d;
    color: #e0e0e0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    min-height: 100vh;
    padding: 32px 16px;
  }
  .header {
    text-align: center;
    margin-bottom: 36px;
  }
  .header h1 {
    font-size: 2rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.5px;
  }
  .header h1 span { color: #e50914; }
  .status-dot {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: #22c55e;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  .badge {
    display: inline-block;
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 0.8rem;
    color: #888;
    margin-top: 10px;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    max-width: 960px;
    margin: 0 auto 32px;
  }
  .card {
    background: #161616;
    border: 1px solid #242424;
    border-radius: 14px;
    padding: 22px 20px;
    text-align: center;
    transition: border-color 0.2s;
  }
  .card:hover { border-color: #3a3a3a; }
  .card .icon { font-size: 1.6rem; margin-bottom: 8px; }
  .card .value {
    font-size: 2rem;
    font-weight: 700;
    color: #fff;
    line-height: 1.1;
  }
  .card .label {
    font-size: 0.78rem;
    color: #666;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .card.green  .value { color: #22c55e; }
  .card.red    .value { color: #ef4444; }
  .card.yellow .value { color: #eab308; }
  .card.blue   .value { color: #3b82f6; }
  .card.purple .value { color: #a855f7; }
  .card.orange .value { color: #f97316; }

  .section-title {
    max-width: 960px;
    margin: 0 auto 14px;
    font-size: 0.85rem;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .activity-table {
    max-width: 960px;
    margin: 0 auto;
    background: #161616;
    border: 1px solid #242424;
    border-radius: 14px;
    overflow: hidden;
  }
  .activity-table table {
    width: 100%;
    border-collapse: collapse;
  }
  .activity-table th {
    background: #1e1e1e;
    color: #555;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 12px 16px;
    text-align: left;
  }
  .activity-table td {
    padding: 10px 16px;
    font-size: 0.85rem;
    border-top: 1px solid #1e1e1e;
  }
  .activity-table tr:hover td { background: #1a1a1a; }
  .pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .pill.hit     { background: #14532d; color: #4ade80; }
  .pill.invalid { background: #450a0a; color: #f87171; }
  .pill.free    { background: #1e3a5f; color: #60a5fa; }
  .pill.on_hold { background: #422006; color: #fb923c; }
  .pill.error   { background: #2d1b1b; color: #fca5a5; }

  .footer {
    text-align: center;
    color: #333;
    font-size: 0.78rem;
    margin-top: 40px;
  }
  #refresh-bar {
    position: fixed;
    top: 0; left: 0;
    height: 2px;
    background: #e50914;
    transition: width 0.1s linear;
    width: 0%;
  }
</style>
</head>
<body>
<div id="refresh-bar"></div>
<div class="header">
  <h1>🎬 Netflix Bot <span>Status</span></h1>
  <div class="badge"><span class="status-dot"></span>Online · Auto-refresh every 10s</div>
</div>

<div class="grid" id="grid">
  <div class="card"><div class="icon">👥</div><div class="value" id="val-users">—</div><div class="label">Unique Users</div></div>
  <div class="card blue"><div class="icon">🔍</div><div class="value" id="val-checks">—</div><div class="label">Total Checks</div></div>
  <div class="card green"><div class="icon">✅</div><div class="value" id="val-hits">—</div><div class="label">Hits</div></div>
  <div class="card red"><div class="icon">❌</div><div class="value" id="val-invalids">—</div><div class="label">Invalid</div></div>
  <div class="card yellow"><div class="icon">🔓</div><div class="value" id="val-frees">—</div><div class="label">Free (No Sub)</div></div>
  <div class="card orange"><div class="icon">⏸️</div><div class="value" id="val-onhold">—</div><div class="label">On Hold</div></div>
  <div class="card purple"><div class="icon">🚀</div><div class="value" id="val-cpm">—</div><div class="label">Checks / Min</div></div>
  <div class="card green"><div class="icon">🎯</div><div class="value" id="val-hitrate">—</div><div class="label">Hit Rate %</div></div>
  <div class="card"><div class="icon">⏱️</div><div class="value" id="val-uptime" style="font-size:1.2rem">—</div><div class="label">Uptime</div></div>
</div>

<div class="section-title">Recent Activity</div>
<div class="activity-table">
  <table>
    <thead><tr><th>Time</th><th>Status</th><th>Source</th></tr></thead>
    <tbody id="activity-body"><tr><td colspan="3" style="color:#444;text-align:center;padding:20px">No activity yet</td></tr></tbody>
  </table>
</div>

<div class="footer">Netflix Cookie Checker Bot · Dashboard</div>

<script>
let progress = 0;
const bar = document.getElementById('refresh-bar');
const INTERVAL = 10000;

function statusPill(s) {
  const map = {hit:'hit',invalid:'invalid',free:'free',on_hold:'on_hold',error:'error'};
  const cls = map[s] || 'error';
  const labels = {hit:'✅ Hit',invalid:'❌ Invalid',free:'🔓 Free',on_hold:'⏸️ On Hold',error:'⚠️ Error'};
  return `<span class="pill ${cls}">${labels[s] || s}</span>`;
}

async function refresh() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('val-users').textContent   = d.total_users;
    document.getElementById('val-checks').textContent  = d.total_checks;
    document.getElementById('val-hits').textContent    = d.total_hits;
    document.getElementById('val-invalids').textContent= d.total_invalids;
    document.getElementById('val-frees').textContent   = d.total_frees;
    document.getElementById('val-onhold').textContent  = d.total_on_hold;
    document.getElementById('val-cpm').textContent     = d.checks_per_min;
    document.getElementById('val-hitrate').textContent = d.hit_rate + '%';
    document.getElementById('val-uptime').textContent  = d.uptime;

    const tbody = document.getElementById('activity-body');
    if (d.activity && d.activity.length > 0) {
      tbody.innerHTML = d.activity.map(a =>
        `<tr><td style="color:#555">${a.time}</td><td>${statusPill(a.status)}</td><td style="color:#888;font-size:0.8rem">${a.source}</td></tr>`
      ).join('');
    }
  } catch(e) {}
}

function startProgressBar() {
  progress = 0;
  bar.style.width = '0%';
  const step = 100 / (INTERVAL / 100);
  const iv = setInterval(() => {
    progress += step;
    bar.style.width = Math.min(progress, 98) + '%';
    if (progress >= 100) { clearInterval(iv); bar.style.width = '0%'; }
  }, 100);
}

refresh();
setInterval(() => { startProgressBar(); refresh(); }, INTERVAL);
startProgressBar();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/stats")
def api_stats():
    return jsonify(stats_tracker.get_stats())


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


def start_dashboard(port: int = 5000) -> None:
    """Start the Flask dashboard in a daemon thread."""
    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)

    t = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
