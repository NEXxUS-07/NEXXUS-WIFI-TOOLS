"""
NetVision — Web Dashboard
Serves a beautiful browser-based UI at http://localhost:8080 with:
  • Interactive Leaflet.js map with live traffic destinations
  • Real-time browsing feed with clickable links
  • Device profiles and fingerprinting
  • Browsing timeline per device
  • Alerts panel
  • Network control (kick/block/throttle)
  • Search queries and chat detection
  • File downloads and credential captures
"""

import json
import threading
import time
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the web dashboard."""

    # Reference to the web dashboard instance (set by WebDashboard)
    dashboard = None

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._serve_html()
        elif path == "/api/status":
            self._serve_json(self.dashboard.get_status())
        elif path == "/api/packets":
            self._serve_json(self.dashboard.get_packets())
        elif path == "/api/devices":
            self._serve_json(self.dashboard.get_devices())
        elif path == "/api/alerts":
            self._serve_json(self.dashboard.get_alerts())
        elif path == "/api/timeline":
            params = parse_qs(parsed.query)
            ip = params.get("ip", [None])[0]
            self._serve_json(self.dashboard.get_timeline(ip))
        elif path == "/api/geo":
            self._serve_json(self.dashboard.get_geo_data())
        elif path == "/api/downloads":
            self._serve_json(self.dashboard.get_downloads())
        elif path == "/api/credentials":
            self._serve_json(self.dashboard.get_credentials())
        elif path == "/api/chats":
            self._serve_json(self.dashboard.get_chats())
        elif path == "/api/blocked":
            self._serve_json(self.dashboard.get_blocked_devices())
        elif path == "/api/control":
            self._serve_json(self.dashboard.get_control_status())
        elif path == "/api/wifi_kill_status":
            self._serve_json(self.dashboard.get_wifi_kill_status())
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if parsed.path == "/api/kick":
            result = self.dashboard.kick_device(body.get("ip"), body.get("duration", 30))
            self._serve_json({"ok": result})
        elif parsed.path == "/api/disconnect":
            result = self.dashboard.disconnect_device(body.get("ip"), body.get("duration", 0))
            self._serve_json({"ok": result})
        elif parsed.path == "/api/reconnect":
            result = self.dashboard.reconnect_device(body.get("ip"))
            self._serve_json({"ok": result})
        elif parsed.path == "/api/block":
            result = self.dashboard.block_site(body.get("ip"), body.get("domain"))
            self._serve_json({"ok": result})
        elif parsed.path == "/api/throttle":
            result = self.dashboard.throttle_device(body.get("ip"), body.get("rate", 100))
            self._serve_json({"ok": result})
        elif parsed.path == "/api/alert_rule":
            self.dashboard.add_alert_rule(body)
            self._serve_json({"ok": True})
        elif parsed.path == "/api/wifi_kill":
            result = self.dashboard.wifi_kill_all()
            self._serve_json(result)
        elif parsed.path == "/api/wifi_restore":
            result = self.dashboard.wifi_restore_all()
            self._serve_json(result)
        else:
            self.send_error(404)

    def _serve_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())

    def _serve_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())


class WebDashboard:
    """Manages the web dashboard and provides API endpoints."""

    def __init__(self, spy=None, scanner=None, geo_mapper=None,
                 fingerprinter=None, alert_system=None, interceptors=None,
                 controller=None, wifi_blocker=None, port=8080):
        self.spy = spy
        self.scanner = scanner
        self.geo_mapper = geo_mapper
        self.fingerprinter = fingerprinter
        self.alert_system = alert_system
        self.interceptors = interceptors or {}
        self.controller = controller
        self.wifi_blocker = wifi_blocker
        self.port = port
        self._server = None
        self._thread = None
        self._wifi_killed = False
        self._wifi_kill_count = 0

    def start(self):
        """Start the web dashboard server."""
        DashboardHandler.dashboard = self
        try:
            self._server = HTTPServer(("0.0.0.0", self.port), DashboardHandler)
            self._server.socket.setsockopt(__import__('socket').SOL_SOCKET, __import__('socket').SO_REUSEADDR, 1)
        except OSError as e:
            if "Address already in use" in str(e):
                # Kill whatever is holding the port and retry
                import subprocess
                subprocess.run(["fuser", "-k", f"{self.port}/tcp"], capture_output=True)
                import time; time.sleep(1)
                self._server = HTTPServer(("0.0.0.0", self.port), DashboardHandler)
                self._server.socket.setsockopt(__import__('socket').SOL_SOCKET, __import__('socket').SO_REUSEADDR, 1)
            else:
                raise
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()

    # ── API Methods ──────────────────────────────────────────────────

    def get_status(self):
        stats = self.spy.get_stats() if self.spy else {}
        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "uptime": str(datetime.now() - datetime.now()).split(".")[0],
            "stats": stats,
            "device_count": len(self.scanner.devices) if self.scanner else 0,
            "alert_count": self.alert_system.get_stats()["total"] if self.alert_system else 0,
        }

    def get_packets(self):
        if self.spy:
            return self.spy.get_all_recent(limit=50)
        return []

    def get_devices(self):
        result = []
        if self.scanner:
            for dev in self.scanner.get_devices():
                info = {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "hostname": dev.hostname,
                    "display_name": getattr(dev, 'display_name', None) or dev.hostname,
                    "vendor": dev.vendor,
                    "is_online": dev.is_online,
                    "first_seen": dev.first_seen.strftime("%H:%M:%S"),
                }
                if self.fingerprinter:
                    profile = self.fingerprinter.get_profile(dev.ip)
                    if profile:
                        info["profile"] = profile.to_dict()
                if self.spy:
                    sites = self.spy.get_websites(dev.ip, limit=10)
                    info["top_sites"] = sites
                    info["searches"] = self.spy.get_searches(dev.ip, limit=5)
                result.append(info)
        return result

    def get_alerts(self):
        if self.alert_system:
            return self.alert_system.get_alerts(limit=50)
        return []

    def get_timeline(self, device_ip=None):
        timeline = self.interceptors.get("timeline")
        if timeline:
            if device_ip:
                return timeline.get_timeline(device_ip, limit=100)
            return timeline.get_all_timelines(limit=100)
        return []

    def get_geo_data(self):
        locations = []
        if self.geo_mapper:
            for ip, geo in self.geo_mapper.get_all_locations().items():
                locations.append({
                    "ip": ip,
                    "lat": geo.lat,
                    "lon": geo.lon,
                    "city": geo.city,
                    "country": geo.country,
                    "country_code": geo.country_code,
                    "isp": geo.isp,
                })
        return locations

    def get_downloads(self):
        tracker = self.interceptors.get("file_tracker")
        if tracker:
            return tracker.get_downloads(limit=50)
        return []

    def get_credentials(self):
        sniffer = self.interceptors.get("credential_sniffer")
        if sniffer:
            return sniffer.get_credentials(limit=30)
        return []

    def get_chats(self):
        detector = self.interceptors.get("chat_detector")
        if detector:
            return detector.get_active_chats()
        return {}

    def get_control_status(self):
        if self.controller:
            return self.controller.get_status()
        return {}

    def kick_device(self, ip, duration=30):
        if self.controller and ip:
            return self.controller.kick_device(ip, duration=duration)
        return False

    def disconnect_device(self, ip, duration=0):
        """Persistently disconnect a device using WiFi Blocker."""
        if self.wifi_blocker and ip:
            try:
                self.wifi_blocker.block_device(target_ip=ip, duration=duration)
                return True
            except Exception:
                pass
        # Fallback to controller kick
        if self.controller and ip:
            return self.controller.kick_device(ip, duration=duration or 9999)
        return False

    def reconnect_device(self, ip):
        """Reconnect a previously disconnected device."""
        if self.wifi_blocker and ip:
            try:
                self.wifi_blocker.unblock_device(ip)
                return True
            except Exception:
                pass
        return False

    def get_blocked_devices(self):
        """Get list of currently blocked/disconnected devices."""
        if self.wifi_blocker:
            return self.wifi_blocker.get_blocked_devices()
        return []

    def block_site(self, ip, domain):
        if self.controller and ip and domain:
            return self.controller.block_site(ip, domain)
        return False

    def throttle_device(self, ip, rate=100):
        if self.controller and ip:
            return self.controller.throttle_device(ip, rate_kbps=rate)
        return False

    def add_alert_rule(self, rule_data):
        if self.alert_system:
            self.alert_system.add_rule(
                rule_data.get("name", "Custom"),
                rule_data.get("type", "domain"),
                rule_data.get("pattern", ""),
                rule_data.get("severity", "medium"),
            )

    def wifi_kill_all(self):
        """Kill WiFi for ALL devices on the network — nobody can access WiFi."""
        if not self.wifi_blocker:
            return {"ok": False, "error": "WiFi Blocker not available"}
        if not self.scanner:
            return {"ok": False, "error": "Scanner not available"}

        try:
            # Get all devices on the network
            devices = self.scanner.get_devices()
            my_ip = self.scanner.local_ip if self.scanner else None
            gateway_ip = self.wifi_blocker.gateway_ip

            # Build device list excluding ourselves and the gateway
            keep_ips = [gateway_ip]
            if my_ip:
                keep_ips.append(my_ip)

            device_list = []
            for dev in devices:
                if dev.ip not in keep_ips:
                    device_list.append((dev.ip, dev.mac, getattr(dev, 'display_name', '') or dev.hostname or ''))

            if not device_list:
                return {"ok": False, "error": "No devices found to block"}

            count = self.wifi_blocker.block_all_except(keep_ips, device_list, duration=0)
            self._wifi_killed = True
            self._wifi_kill_count = count
            return {"ok": True, "blocked": count, "total_devices": len(device_list)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def wifi_restore_all(self):
        """Restore WiFi for all blocked devices."""
        if not self.wifi_blocker:
            return {"ok": False, "error": "WiFi Blocker not available"}
        try:
            self.wifi_blocker.unblock_all()
            self._wifi_killed = False
            self._wifi_kill_count = 0
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_wifi_kill_status(self):
        """Get current WiFi kill switch status."""
        blocked = self.get_blocked_devices()
        active_count = len(blocked) if isinstance(blocked, list) else 0
        return {
            "active": self._wifi_killed,
            "blocked_count": active_count,
        }


# ═══════════════════════════════════════════════════════════════════════
# EMBEDDED HTML DASHBOARD
# ═══════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetVision — WiFi Intelligence Dashboard</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e17;--card:#111827;--border:#1e293b;--text:#e2e8f0;--dim:#64748b;
--cyan:#22d3ee;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--magenta:#c084fc;
--blue:#3b82f6;--glass:rgba(17,24,39,0.85)}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);overflow-x:hidden}
code,.mono{font-family:'JetBrains Mono',monospace}

/* Header */
.header{background:linear-gradient(135deg,#0f172a,#1e1b4b);border-bottom:1px solid var(--border);
padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:20px;font-weight:700;background:linear-gradient(135deg,var(--cyan),var(--magenta));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .stats{display:flex;gap:16px;font-size:13px}
.header .stat{display:flex;align-items:center;gap:4px}
.stat .dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.dot.green{background:var(--green)}.dot.red{background:var(--red)}.dot.cyan{background:var(--cyan)}

/* Grid */
.grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding:12px;height:calc(100vh - 56px)}
.grid.two{grid-template-columns:2fr 1fr}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;
display:flex;flex-direction:column}
.card-header{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;
align-items:center;justify-content:space-between;font-size:13px;font-weight:600}
.card-header .icon{font-size:16px;margin-right:6px}
.card-body{padding:10px;overflow-y:auto;flex:1;font-size:12px}

/* Map */
#map{height:100%;min-height:250px;border-radius:0 0 12px 12px;background:#0a0e17}

/* Tables */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:6px 8px;color:var(--dim);font-weight:500;font-size:11px;
border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card)}
td{padding:5px 8px;border-bottom:1px solid rgba(30,41,59,0.5);font-size:12px}
tr:hover{background:rgba(34,211,238,0.05)}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}

/* Severity badges */
.badge{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;display:inline-block}
.badge.critical{background:rgba(239,68,68,0.2);color:var(--red);border:1px solid var(--red)}
.badge.high{background:rgba(245,158,11,0.2);color:var(--yellow);border:1px solid var(--yellow)}
.badge.medium{background:rgba(59,130,246,0.2);color:var(--blue);border:1px solid var(--blue)}
.badge.low{background:rgba(100,116,139,0.2);color:var(--dim);border:1px solid var(--dim)}

/* Buttons */
.btn{padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:var(--card);
color:var(--text);cursor:pointer;font-size:11px;transition:all 0.2s}
.btn:hover{background:rgba(34,211,238,0.1);border-color:var(--cyan)}
.btn.danger{border-color:var(--red);color:var(--red)}
.btn.danger:hover{background:rgba(239,68,68,0.15)}

/* WiFi Kill Button */
.wifi-kill-btn{padding:6px 18px;border-radius:8px;border:2px solid #ef4444;background:linear-gradient(135deg,rgba(239,68,68,0.15),rgba(220,38,38,0.3));
  color:#ff4444;cursor:pointer;font-size:13px;font-weight:800;letter-spacing:1px;text-transform:uppercase;
  transition:all 0.3s ease;position:relative;overflow:hidden;text-shadow:0 0 8px rgba(239,68,68,0.5);
  box-shadow:0 0 15px rgba(239,68,68,0.2),inset 0 0 15px rgba(239,68,68,0.1)}
.wifi-kill-btn:hover{background:linear-gradient(135deg,rgba(239,68,68,0.4),rgba(220,38,38,0.6));
  box-shadow:0 0 30px rgba(239,68,68,0.5),inset 0 0 20px rgba(239,68,68,0.2);transform:scale(1.05);
  text-shadow:0 0 15px rgba(239,68,68,0.8)}
.wifi-kill-btn:active{transform:scale(0.95)}
.wifi-kill-btn.active{background:linear-gradient(135deg,#dc2626,#991b1b);color:#fff;border-color:#ff0000;
  animation:killPulse 1.5s infinite;box-shadow:0 0 40px rgba(239,68,68,0.6),inset 0 0 20px rgba(239,68,68,0.3)}
@keyframes killPulse{0%,100%{box-shadow:0 0 20px rgba(239,68,68,0.4),inset 0 0 15px rgba(239,68,68,0.2)}
  50%{box-shadow:0 0 50px rgba(239,68,68,0.8),inset 0 0 30px rgba(239,68,68,0.4)}}

.wifi-restore-btn{padding:6px 18px;border-radius:8px;border:2px solid #10b981;background:linear-gradient(135deg,rgba(16,185,129,0.15),rgba(5,150,105,0.3));
  color:#10b981;cursor:pointer;font-size:13px;font-weight:800;letter-spacing:1px;text-transform:uppercase;
  transition:all 0.3s ease;text-shadow:0 0 8px rgba(16,185,129,0.5);
  box-shadow:0 0 15px rgba(16,185,129,0.2),inset 0 0 15px rgba(16,185,129,0.1)}
.wifi-restore-btn:hover{background:linear-gradient(135deg,rgba(16,185,129,0.4),rgba(5,150,105,0.6));
  box-shadow:0 0 30px rgba(16,185,129,0.5);transform:scale(1.05)}
.wifi-restore-btn:active{transform:scale(0.95)}

/* Scrollbar */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}

/* Proto badges */
.proto{padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}
.proto.dns{background:rgba(34,211,238,0.15);color:var(--cyan)}
.proto.https{background:rgba(16,185,129,0.15);color:var(--green)}
.proto.http{background:rgba(245,158,11,0.15);color:var(--yellow)}
.proto.search{background:rgba(192,132,252,0.15);color:var(--magenta)}

/* Chat apps */
.chat-app{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;
font-size:11px;margin:2px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3)}

/* Device card */
.device-card{padding:8px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px;
transition:all 0.2s;cursor:pointer}
.device-card:hover{border-color:var(--cyan);background:rgba(34,211,238,0.05)}
.device-card .ip{font-weight:600;color:var(--cyan);font-size:13px}
.device-card .meta{color:var(--dim);font-size:11px;margin-top:2px}
.device-card .actions{margin-top:6px;display:flex;gap:4px}

/* Responsive */
@media(max-width:1200px){.grid{grid-template-columns:1fr 1fr}}
@media(max-width:768px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="header">
  <h1>🕵️ NetVision Intelligence</h1>
  <div class="stats">
    <div class="stat"><span class="dot green"></span><span id="s-devices">0</span> devices</div>
    <div class="stat"><span class="dot cyan"></span><span id="s-packets">0</span> packets</div>
    <div class="stat"><span class="dot red"></span><span id="s-alerts">0</span> alerts</div>
    <div class="stat" id="s-time"></div>
    <div style="margin-left:12px;display:flex;gap:6px;align-items:center">
      <button id="wifi-kill-btn" class="wifi-kill-btn" onclick="wifiKill()">
        ☠ WIFI KILL
      </button>
      <button id="wifi-restore-btn" class="wifi-restore-btn" style="display:none" onclick="wifiRestore()">
        ⚡ RESTORE ALL
      </button>
      <span id="wifi-kill-status" style="font-size:11px;color:var(--dim)"></span>
    </div>
  </div>
</div>

<div class="grid" style="grid-template-columns:1fr 2fr 1fr;grid-template-rows:1fr 1fr;height:calc(100vh - 56px)">

  <!-- Devices -->
  <div class="card" style="grid-row:span 2">
    <div class="card-header"><span><span class="icon">📡</span>Devices</span></div>
    <div class="card-body" id="devices-panel"></div>
  </div>

  <!-- Live Feed -->
  <div class="card">
    <div class="card-header"><span><span class="icon">🔴</span>Live Browsing Feed</span>
      <span style="color:var(--dim);font-size:11px">click links to visit</span></div>
    <div class="card-body" id="feed-panel"><table><thead><tr>
      <th>Time</th><th>Device</th><th>Type</th><th>URL / Domain</th>
    </tr></thead><tbody id="feed-body"></tbody></table></div>
  </div>

  <!-- Map -->
  <div class="card">
    <div class="card-header"><span><span class="icon">📍</span>Live Location Tracker</span></div>
    <div id="map"></div>
  </div>

  <!-- Alerts -->
  <div class="card">
    <div class="card-header"><span><span class="icon">🚨</span>Alerts</span></div>
    <div class="card-body" id="alerts-panel"><table><thead><tr>
      <th>Time</th><th>Severity</th><th>Rule</th><th>Device</th><th>Details</th>
    </tr></thead><tbody id="alerts-body"></tbody></table></div>
  </div>

  <!-- Right sidebar: searches + chats + downloads -->
  <div class="card">
    <div class="card-header"><span><span class="icon">🔎</span>Searches & Activity</span></div>
    <div class="card-body">
      <div id="searches-panel" style="margin-bottom:12px"></div>
      <div style="border-top:1px solid var(--border);padding-top:8px">
        <div style="font-weight:600;font-size:11px;color:var(--dim);margin-bottom:6px">💬 Chat Apps Detected</div>
        <div id="chats-panel"></div>
      </div>
      <div style="border-top:1px solid var(--border);padding-top:8px;margin-top:8px">
        <div style="font-weight:600;font-size:11px;color:var(--dim);margin-bottom:6px">📁 Downloads</div>
        <div id="downloads-panel"></div>
      </div>
    </div>
  </div>

</div>

<script>
// Map (wrapped in try/catch so dashboard works even if Leaflet CDN fails)
let map = null;
const markers = {};
try{
  map = L.map('map',{zoomControl:false}).setView([20,0],2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
    attribution:'NetVision',maxZoom:19,
  }).addTo(map);
}catch(e){console.warn('Map init failed:',e)}

function addMarker(loc){
  if(!map) return;
  try{
    const key = loc.ip;
    if(markers[key]){markers[key].setLatLng([loc.lat,loc.lon]);return}
    const m = L.circleMarker([loc.lat,loc.lon],{
      radius:6,fillColor:'#ef4444',color:'#ef4444',weight:1,opacity:0.8,fillOpacity:0.5
    }).addTo(map);
    m.bindPopup(`<b>${loc.city}, ${loc.country}</b><br>${loc.ip}<br>${loc.isp||''}`);
    markers[key] = m;
  }catch(e){}
}

// Proto badge
function protoBadge(p){
  const cls = p.toLowerCase().replace('/','');
  return `<span class="proto ${cls}">${p}</span>`;
}

// Severity badge
function sevBadge(s){
  return `<span class="badge ${s}">${s.toUpperCase()}</span>`;
}

// Refresh
async function refresh(){
  try{
    // Packets
    const pkts = await(await fetch('/api/packets')).json();
    const fb = document.getElementById('feed-body');
    fb.innerHTML = pkts.reverse().map(p=>{
      const url = p.url || (p.domain ? `https://${p.domain}/` : '');
      const link = url ? `<a href="${url}" target="_blank">🔗 ${(p.domain||url).substring(0,40)}</a>` :
                         (p.domain || p.dst || '?');
      const search = p.search_query ? `🔎 "${p.search_query}"` : '';
      return `<tr><td class="mono">${p.time||''}</td><td>${p.src||''}</td>
        <td>${protoBadge(p.proto||'?')}</td><td>${search||link}</td></tr>`;
    }).join('');

    // Devices
    const devs = await(await fetch('/api/devices')).json();
    document.getElementById('s-devices').textContent = devs.length;
    const dp = document.getElementById('devices-panel');
    // Fetch blocked device list
    let blockedIps = [];
    try { blockedIps = (await(await fetch('/api/blocked')).json()).map(b=>b.ip); } catch(e){}

    dp.innerHTML = devs.map(d=>{
      const profile = d.profile ? `${d.profile.brand||''} ${d.profile.model||''} (${d.profile.os||'?'})` : '';
      const sites = (d.top_sites||[]).slice(0,3).map(s=>`<a href="https://${s[0]}/" target="_blank">${s[0]}</a>`).join(', ');
      const online = d.is_online ? '<span class="dot green" style="display:inline-block"></span>' : '<span class="dot" style="background:var(--dim);display:inline-block"></span>';
      const isBlocked = blockedIps.includes(d.ip);
      const devName = d.display_name || d.hostname || d.vendor || '';
      return `<div class="device-card" style="${isBlocked?'border-color:var(--red);background:rgba(239,68,68,0.08)':''}">
        <div class="ip">${online} ${d.ip} ${isBlocked?'<span class="badge critical">DISCONNECTED</span>':''}</div>
        <div style="font-weight:600;color:var(--cyan);font-size:13px;margin-top:2px">${devName}</div>
        <div class="meta">${d.vendor||''} · MAC: ${d.mac||''}</div>
        ${profile?`<div class="meta">${profile}</div>`:''}
        ${sites?`<div class="meta">Sites: ${sites}</div>`:''}
        <div class="actions">
          ${isBlocked
            ? `<button class="btn" style="border-color:var(--green);color:var(--green);font-weight:700" onclick="reconnect('${d.ip}')">⚡ RECONNECT</button>`
            : `<button class="btn danger" style="font-weight:700" onclick="disconnect('${d.ip}')">⛔ DISCONNECT</button>`
          }
          <button class="btn danger" onclick="kick('${d.ip}')">Kick 30s</button>
          <button class="btn" onclick="throttle('${d.ip}')">Throttle</button>
        </div>
      </div>`;
    }).join('');

    // Alerts
    const alerts = await(await fetch('/api/alerts')).json();
    document.getElementById('s-alerts').textContent = alerts.length;
    const ab = document.getElementById('alerts-body');
    ab.innerHTML = alerts.reverse().slice(0,15).map(a=>`<tr>
      <td class="mono">${a.time}</td><td>${sevBadge(a.severity)}</td>
      <td>${a.rule}</td><td>${a.device}</td><td style="font-size:11px">${a.details.substring(0,30)}</td>
    </tr>`).join('');

    // Geo
    const geo = await(await fetch('/api/geo')).json();
    geo.forEach(addMarker);

    // Searches (from packets)
    const searches = pkts.filter(p=>p.search_query);
    const sp = document.getElementById('searches-panel');
    sp.innerHTML = searches.length ? searches.slice(0,6).map(s=>
      `<div style="margin-bottom:4px"><span style="color:var(--dim);font-size:11px">${s.src||''}</span>
       <span style="color:var(--magenta);font-weight:600"> 🔎 "${s.search_query}"</span></div>`
    ).join('') : '<span style="color:var(--dim)">No searches yet...</span>';

    // Chats
    const chats = await(await fetch('/api/chats')).json();
    const cp = document.getElementById('chats-panel');
    let chatHtml = '';
    for(const[ip,info]of Object.entries(chats)){
      if(info.apps && info.apps.length){
        chatHtml += `<div style="margin-bottom:4px"><span style="color:var(--dim)">${ip}:</span> `;
        chatHtml += info.apps.map(a=>`<span class="chat-app">${a}</span>`).join(' ');
        chatHtml += '</div>';
      }
    }
    cp.innerHTML = chatHtml || '<span style="color:var(--dim)">No chat apps detected</span>';

    // Downloads
    const downloads = await(await fetch('/api/downloads')).json();
    const dlp = document.getElementById('downloads-panel');
    dlp.innerHTML = downloads.length ? downloads.slice(-5).reverse().map(d=>
      `<div style="margin-bottom:4px;font-size:11px">
        <span style="color:var(--yellow)">${d.type}</span>
        <a href="${d.url}" target="_blank">${d.filename}</a>
        <span style="color:var(--dim)">(${d.device_ip})</span>
      </div>`
    ).join('') : '<span style="color:var(--dim)">No downloads yet</span>';

    // Stats
    const status = await(await fetch('/api/status')).json();
    document.getElementById('s-packets').textContent = status.stats?.total_packets || 0;
    document.getElementById('s-time').textContent = status.time;

  }catch(e){console.error(e)}
}

// Actions
async function kick(ip){
  if(confirm(`Kick ${ip} off the network for 30s?`)){
    await fetch('/api/kick',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip,duration:30})});
  }
}
async function disconnect(ip){
  if(confirm(`⛔ DISCONNECT ${ip} from WiFi?\n\nThe device will be unable to use the internet until you reconnect it.`)){
    const r = await fetch('/api/disconnect',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip,duration:0})});
    const j = await r.json();
    if(j.ok) alert(`✅ ${ip} has been DISCONNECTED from the network.`);
    else alert('Failed to disconnect. Check permissions.');
    refresh();
  }
}
async function reconnect(ip){
  if(confirm(`⚡ Reconnect ${ip} back to WiFi?`)){
    const r = await fetch('/api/reconnect',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip})});
    const j = await r.json();
    if(j.ok) alert(`✅ ${ip} has been RECONNECTED.`);
    else alert('Failed to reconnect.');
    refresh();
  }
}
async function throttle(ip){
  const rate = prompt(`Throttle ${ip} to how many kbps?`,'100');
  if(rate){
    await fetch('/api/throttle',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip,rate:parseInt(rate)})});
  }
}

// ═══ WiFi Kill Switch ═══
async function wifiKill(){
  if(!confirm('☠ WIFI KILL — NUCLEAR OPTION\n\n'
    + 'This will DISCONNECT every single device\n'
    + 'from the WiFi network.\n\n'
    + 'Nobody will be able to access the internet\n'
    + 'until you restore it.\n\n'
    + 'Proceed with WiFi Kill?')) return;

  const btn = document.getElementById('wifi-kill-btn');
  btn.textContent = '⏳ KILLING...';
  btn.disabled = true;

  try{
    const r = await fetch('/api/wifi_kill',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    const j = await r.json();
    if(j.ok){
      btn.classList.add('active');
      btn.textContent = `☠ KILLED (${j.blocked})`;
      document.getElementById('wifi-restore-btn').style.display = 'inline-block';
      document.getElementById('wifi-kill-status').textContent = `${j.blocked} devices blocked`;
      document.getElementById('wifi-kill-status').style.color = '#ef4444';
    } else {
      alert('Kill failed: ' + (j.error || 'Unknown error'));
      btn.textContent = '☠ WIFI KILL';
    }
  } catch(e){
    alert('Error: ' + e.message);
    btn.textContent = '☠ WIFI KILL';
  }
  btn.disabled = false;
  refresh();
}

async function wifiRestore(){
  if(!confirm('⚡ RESTORE ALL DEVICES\n\nThis will reconnect everyone back to the network.')) return;

  const btn = document.getElementById('wifi-restore-btn');
  btn.textContent = '⏳ RESTORING...';
  btn.disabled = true;

  try{
    const r = await fetch('/api/wifi_restore',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    const j = await r.json();
    if(j.ok){
      document.getElementById('wifi-kill-btn').classList.remove('active');
      document.getElementById('wifi-kill-btn').textContent = '☠ WIFI KILL';
      btn.style.display = 'none';
      document.getElementById('wifi-kill-status').textContent = '';
    } else {
      alert('Restore failed: ' + (j.error || 'Unknown error'));
    }
  } catch(e){
    alert('Error: ' + e.message);
  }
  btn.textContent = '⚡ RESTORE ALL';
  btn.disabled = false;
  refresh();
}

// Sync kill button state on load
async function syncKillStatus(){
  try{
    const r = await fetch('/api/wifi_kill_status');
    const j = await r.json();
    const killBtn = document.getElementById('wifi-kill-btn');
    const restoreBtn = document.getElementById('wifi-restore-btn');
    const statusEl = document.getElementById('wifi-kill-status');
    if(j.active && j.blocked_count > 0){
      killBtn.classList.add('active');
      killBtn.textContent = `☠ KILLED (${j.blocked_count})`;
      restoreBtn.style.display = 'inline-block';
      statusEl.textContent = `${j.blocked_count} devices blocked`;
      statusEl.style.color = '#ef4444';
    } else {
      killBtn.classList.remove('active');
      killBtn.textContent = '☠ WIFI KILL';
      restoreBtn.style.display = 'none';
      statusEl.textContent = '';
    }
  }catch(e){}
}

// Auto-refresh
setInterval(()=>{refresh();syncKillStatus()}, 2000);
refresh();
syncKillStatus();
</script>
</body>
</html>"""
