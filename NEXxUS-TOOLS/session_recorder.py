"""
NetVision — Session Recorder (PCAP)
Saves entire capture sessions as Wireshark-compatible .pcap files.
Allows session replay and HTML report export.
"""

import os
import json
import threading
import time
from datetime import datetime
from collections import deque

try:
    from scapy.all import wrpcap, PcapWriter, Packet
    SCAPY_PCAP = True
except ImportError:
    SCAPY_PCAP = False


class SessionRecorder:
    """Records packets to PCAP files and generates HTML reports."""

    def __init__(self, output_dir=None, interface="wlan0"):
        self.interface = interface
        self.output_dir = output_dir or os.path.dirname(os.path.abspath(__file__))
        self._running = False
        self._lock = threading.Lock()
        self._writer = None
        self._pcap_file = None
        self._packet_count = 0
        self._start_time = None
        self._session_log = deque(maxlen=5000)

        # Stats
        self._stats = {
            "packets_written": 0,
            "bytes_written": 0,
            "file_size": 0,
        }

    def start(self, target_ips=None):
        """Start recording session."""
        self._running = True
        self._start_time = datetime.now()

        # Create PCAP file
        timestamp = self._start_time.strftime("%Y%m%d_%H%M%S")
        targets_str = "_".join(
            [ip.replace(".", "-") for ip in (target_ips or [])[:3]]
        ) or "all"
        self._pcap_file = os.path.join(
            self.output_dir,
            f"capture_{targets_str}_{timestamp}.pcap",
        )

        if SCAPY_PCAP:
            try:
                self._writer = PcapWriter(
                    self._pcap_file,
                    append=True,
                    sync=True,
                )
            except Exception:
                self._writer = None

        return self._pcap_file

    def write_packet(self, packet):
        """Write a raw scapy packet to the PCAP file."""
        if not self._running or not self._writer:
            return

        try:
            self._writer.write(packet)
            self._packet_count += 1
            self._stats["packets_written"] += 1
            self._stats["bytes_written"] += len(packet)
        except Exception:
            pass

    def log_event(self, event_type, details, device_ip="", domain="", url=""):
        """Log a session event for the HTML report."""
        with self._lock:
            self._session_log.append({
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "timestamp": datetime.now().isoformat(),
                "type": event_type,
                "device": device_ip,
                "domain": domain,
                "url": url,
                "details": details,
            })

    def stop(self):
        """Stop recording and finalize."""
        self._running = False
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass

        # Update file size
        if self._pcap_file and os.path.exists(self._pcap_file):
            self._stats["file_size"] = os.path.getsize(self._pcap_file)

    def export_html_report(self, output_file=None):
        """Generate an HTML report of the session."""
        if not output_file:
            output_file = (self._pcap_file or "session").replace(".pcap", "_report.html")

        events = list(self._session_log)
        duration = ""
        if self._start_time:
            dur = datetime.now() - self._start_time
            duration = str(dur).split(".")[0]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetVision Session Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e2e8f0;padding:20px}}
h1{{font-size:24px;margin-bottom:8px;background:linear-gradient(135deg,#22d3ee,#c084fc);
-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.meta{{color:#64748b;margin-bottom:20px;font-size:14px}}
.stats{{display:flex;gap:20px;margin-bottom:20px}}
.stat-card{{background:#111827;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;flex:1}}
.stat-card h3{{font-size:12px;color:#64748b;margin-bottom:4px}}
.stat-card .value{{font-size:24px;font-weight:700;color:#22d3ee}}
table{{width:100%;border-collapse:collapse;background:#111827;border-radius:8px;overflow:hidden}}
th{{text-align:left;padding:8px 12px;background:#1e293b;color:#64748b;font-size:12px}}
td{{padding:6px 12px;border-bottom:1px solid #1e293b;font-size:13px}}
tr:hover{{background:rgba(34,211,238,0.05)}}
a{{color:#22d3ee;text-decoration:none}}
a:hover{{text-decoration:underline}}
.badge{{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}}
.dns{{background:rgba(34,211,238,0.15);color:#22d3ee}}
.https{{background:rgba(16,185,129,0.15);color:#10b981}}
.http{{background:rgba(245,158,11,0.15);color:#f59e0b}}
.search{{background:rgba(192,132,252,0.15);color:#c084fc}}
.alert{{background:rgba(239,68,68,0.15);color:#ef4444}}
</style>
</head>
<body>
<h1>🕵️ NetVision Session Report</h1>
<div class="meta">
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} •
  Duration: {duration} •
  PCAP: {os.path.basename(self._pcap_file or 'N/A')}
</div>
<div class="stats">
  <div class="stat-card"><h3>PACKETS</h3><div class="value">{self._stats['packets_written']:,}</div></div>
  <div class="stat-card"><h3>DATA</h3><div class="value">{self._fmt_bytes(self._stats['bytes_written'])}</div></div>
  <div class="stat-card"><h3>EVENTS</h3><div class="value">{len(events)}</div></div>
  <div class="stat-card"><h3>PCAP SIZE</h3><div class="value">{self._fmt_bytes(self._stats['file_size'])}</div></div>
</div>
<h2 style="font-size:16px;margin-bottom:8px">📋 Session Timeline</h2>
<table>
<thead><tr><th>Time</th><th>Type</th><th>Device</th><th>Domain</th><th>Details</th></tr></thead>
<tbody>
"""
        for e in events:
            badge_class = e["type"].lower().replace("/", "")
            url_link = ""
            if e.get("url"):
                url_link = f'<a href="{e["url"]}" target="_blank">{e["domain"] or e["url"][:40]}</a>'
            elif e.get("domain"):
                url_link = f'<a href="https://{e["domain"]}/" target="_blank">{e["domain"]}</a>'

            html += f"""<tr>
  <td style="font-family:monospace;color:#64748b">{e['time']}</td>
  <td><span class="badge {badge_class}">{e['type']}</span></td>
  <td>{e['device']}</td>
  <td>{url_link or e.get('domain', '')}</td>
  <td style="font-size:12px;color:#94a3b8">{e['details'][:60]}</td>
</tr>
"""

        html += """</tbody></table>
<div style="margin-top:20px;color:#64748b;font-size:12px;text-align:center">
  NetVision Intelligence Suite — Educational Use Only
</div>
</body></html>"""

        try:
            with open(output_file, "w") as f:
                f.write(html)
            return output_file
        except Exception:
            return None

    def get_stats(self):
        stats = dict(self._stats)
        stats["pcap_file"] = self._pcap_file
        stats["packet_count"] = self._packet_count
        if self._start_time:
            stats["duration"] = str(datetime.now() - self._start_time).split(".")[0]
        return stats

    @staticmethod
    def _fmt_bytes(b):
        if b < 1024:
            return f"{b}B"
        elif b < 1048576:
            return f"{b/1024:.1f}KB"
        elif b < 1073741824:
            return f"{b/1048576:.1f}MB"
        else:
            return f"{b/1073741824:.2f}GB"
