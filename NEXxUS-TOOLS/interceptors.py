"""
NetVision — Credential Sniffer, File Tracker, Image Capture, Chat Detector
Captures HTTP login forms, file downloads, images, and messaging activity.
"""

import re
import os
import threading
from datetime import datetime
from collections import defaultdict, deque
from urllib.parse import unquote_plus, urlparse


class CredentialSniffer:
    """Captures credentials from HTTP POST requests (unencrypted only)."""

    def __init__(self):
        self._credentials = deque(maxlen=200)
        self._lock = threading.Lock()
        self._credential_fields = [
            "user", "username", "login", "email", "mail",
            "pass", "password", "passwd", "pwd", "secret",
            "token", "auth", "key", "pin", "code",
            "phone", "mobile", "account", "id",
        ]

    def analyze_http_payload(self, device_ip, host, method, path, payload, pkt_size=0):
        """Analyze HTTP payload for credentials."""
        if method != "POST":
            return None

        payload_lower = payload.lower()

        # Check if it looks like a form submission
        if "content-type:" not in payload_lower:
            return None

        is_form = ("application/x-www-form-urlencoded" in payload_lower or
                   "multipart/form-data" in payload_lower)

        if not is_form:
            return None

        # Extract POST body (after double newline)
        body = ""
        parts = payload.split("\r\n\r\n", 1)
        if len(parts) > 1:
            body = parts[1]
        else:
            parts = payload.split("\n\n", 1)
            if len(parts) > 1:
                body = parts[1]

        if not body:
            return None

        # Parse form fields
        fields = {}
        for pair in body.split("&"):
            if "=" in pair:
                key, _, value = pair.partition("=")
                key = unquote_plus(key.strip())
                value = unquote_plus(value.strip())
                if key and value:
                    fields[key] = value

        # Check for credential-like fields
        found_user = None
        found_pass = None
        other_sensitive = {}

        for field_name, field_value in fields.items():
            fn = field_name.lower()
            for cred_field in self._credential_fields:
                if cred_field in fn:
                    if "pass" in fn or "pwd" in fn or "secret" in fn:
                        found_pass = (field_name, field_value)
                    elif "user" in fn or "login" in fn or "email" in fn or "mail" in fn:
                        found_user = (field_name, field_value)
                    else:
                        other_sensitive[field_name] = field_value
                    break

        if found_user or found_pass or other_sensitive:
            cred = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "device_ip": device_ip,
                "host": host,
                "url": f"http://{host}{path}",
                "username_field": found_user[0] if found_user else None,
                "username": found_user[1] if found_user else None,
                "password_field": found_pass[0] if found_pass else None,
                "password": found_pass[1] if found_pass else None,
                "other_fields": other_sensitive,
                "all_fields": fields,
            }

            with self._lock:
                self._credentials.append(cred)

            return cred
        return None

    def get_credentials(self, limit=50):
        with self._lock:
            return list(self._credentials)[-limit:]


class FileTracker:
    """Tracks file downloads from HTTP traffic."""

    def __init__(self, save_dir=None):
        self._downloads = deque(maxlen=500)
        self._lock = threading.Lock()
        self.save_dir = save_dir

        # File extensions to track
        self._extensions = {
            "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                        ".txt", ".csv", ".rtf", ".odt"],
            "image": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"],
            "video": [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m3u8", ".ts"],
            "audio": [".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a"],
            "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
            "executable": [".exe", ".msi", ".dmg", ".deb", ".rpm", ".apk", ".ipa",
                          ".sh", ".bat", ".cmd", ".ps1"],
            "code": [".js", ".css", ".html", ".json", ".xml", ".py", ".java"],
            "torrent": [".torrent", ".magnet"],
        }

        self._all_extensions = set()
        for exts in self._extensions.values():
            self._all_extensions.update(exts)

        if save_dir and not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)

    def check_url(self, device_ip, url, host="", content_type="", content_length=0):
        """Check if a URL is a file download."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check extension
        file_type = None
        ext = None
        for ftype, extensions in self._extensions.items():
            for extension in extensions:
                if path.endswith(extension):
                    file_type = ftype
                    ext = extension
                    break
            if file_type:
                break

        # Check Content-Type header
        if not file_type and content_type:
            ct = content_type.lower()
            if "application/pdf" in ct:
                file_type, ext = "document", ".pdf"
            elif "application/zip" in ct:
                file_type, ext = "archive", ".zip"
            elif "application/octet-stream" in ct:
                file_type, ext = "executable", ".bin"
            elif "video/" in ct:
                file_type, ext = "video", ".video"
            elif "audio/" in ct:
                file_type, ext = "audio", ".audio"
            elif "image/" in ct and "svg" not in ct:
                file_type, ext = "image", ".img"

        # Check for streaming segments
        if not file_type:
            if ".m3u8" in path or ".ts" in path or "/manifest" in path:
                file_type, ext = "video", ".stream"

        if file_type:
            filename = os.path.basename(parsed.path) or "unknown"

            download = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "device_ip": device_ip,
                "url": url,
                "host": host,
                "filename": filename,
                "type": file_type,
                "extension": ext,
                "size": content_length,
                "content_type": content_type,
            }

            with self._lock:
                self._downloads.append(download)

            return download
        return None

    def get_downloads(self, limit=50, file_type=None):
        with self._lock:
            downloads = list(self._downloads)
            if file_type:
                downloads = [d for d in downloads if d["type"] == file_type]
            return downloads[-limit:]

    def get_stats(self):
        with self._lock:
            counts = defaultdict(int)
            for d in self._downloads:
                counts[d["type"]] += 1
            return {
                "total": len(self._downloads),
                "by_type": dict(counts),
            }


class ImageCapture:
    """Captures image URLs from HTTP traffic."""

    def __init__(self):
        self._images = deque(maxlen=300)
        self._lock = threading.Lock()
        self._image_extensions = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}

    def check_url(self, device_ip, url, host="", referer=""):
        """Check if URL is an image and capture it."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        is_image = any(path.endswith(ext) for ext in self._image_extensions)

        if is_image:
            img = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "device_ip": device_ip,
                "url": url,
                "host": host,
                "filename": os.path.basename(parsed.path),
                "referer": referer,
            }

            with self._lock:
                self._images.append(img)
            return img
        return None

    def get_images(self, limit=50):
        with self._lock:
            return list(self._images)[-limit:]


class ChatDetector:
    """Detects messaging/chat application usage."""

    def __init__(self):
        self._chat_sessions = defaultdict(lambda: {
            "apps": set(),
            "last_seen": None,
            "packet_count": 0,
        })
        self._chat_log = deque(maxlen=500)
        self._lock = threading.Lock()

        # Chat app signatures
        self._chat_patterns = {
            "WhatsApp": {
                "domains": ["web.whatsapp.com", "whatsapp.com", "wa.me",
                           "chat.whatsapp.com", "mmg.whatsapp.net", "media.whatsapp.net"],
                "ips": [],
                "ports": [5222, 5223, 5228],
            },
            "Telegram": {
                "domains": ["telegram.org", "t.me", "web.telegram.org",
                           "core.telegram.org", "telegram.me"],
                "ips_prefix": ["149.154.", "91.108."],
                "ports": [],
            },
            "Discord": {
                "domains": ["discord.com", "discord.gg", "discordapp.com",
                           "cdn.discordapp.com", "gateway.discord.gg"],
                "ips": [],
                "ports": [],
            },
            "Slack": {
                "domains": ["slack.com", "slack-edge.com", "slack-msgs.com",
                           "slack-files.com", "slack-imgs.com"],
                "ips": [],
                "ports": [],
            },
            "Signal": {
                "domains": ["signal.org", "textsecure-service.whispersystems.org"],
                "ips": [],
                "ports": [],
            },
            "Messenger": {
                "domains": ["messenger.com", "m.me", "edge-chat.messenger.com"],
                "ips": [],
                "ports": [],
            },
            "Skype": {
                "domains": ["skype.com", "lync.com", "sfb.ms"],
                "ips": [],
                "ports": [],
            },
            "Teams": {
                "domains": ["teams.microsoft.com", "teams.live.com"],
                "ips": [],
                "ports": [],
            },
            "Snapchat": {
                "domains": ["snapchat.com", "snap.com", "sc-cdn.net"],
                "ips": [],
                "ports": [],
            },
            "Instagram DM": {
                "domains": ["i.instagram.com/api/v1/direct_v2"],
                "ips": [],
                "ports": [],
            },
        }

    def check(self, device_ip, domain="", dst_ip="", dst_port=0, url=""):
        """Check if activity indicates chat app usage."""
        detected = []
        domain_lower = domain.lower()

        for app_name, signatures in self._chat_patterns.items():
            matched = False

            # Domain match
            for d in signatures.get("domains", []):
                if d in domain_lower:
                    matched = True
                    break

            # IP prefix match
            if not matched and dst_ip:
                for prefix in signatures.get("ips_prefix", []):
                    if dst_ip.startswith(prefix):
                        matched = True
                        break

            # Port match
            if not matched and dst_port:
                if dst_port in signatures.get("ports", []):
                    matched = True

            if matched:
                with self._lock:
                    self._chat_sessions[device_ip]["apps"].add(app_name)
                    self._chat_sessions[device_ip]["last_seen"] = datetime.now()
                    self._chat_sessions[device_ip]["packet_count"] += 1

                    self._chat_log.append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "device_ip": device_ip,
                        "app": app_name,
                        "domain": domain,
                        "dst_ip": dst_ip,
                    })
                detected.append(app_name)

        return detected

    def get_active_chats(self):
        """Get all devices with active chat sessions."""
        with self._lock:
            result = {}
            now = datetime.now()
            for ip, info in self._chat_sessions.items():
                result[ip] = {
                    "apps": list(info["apps"]),
                    "last_seen": info["last_seen"].strftime("%H:%M:%S") if info["last_seen"] else None,
                    "packet_count": info["packet_count"],
                    "active": info["last_seen"] and (now - info["last_seen"]).seconds < 60,
                }
            return result

    def get_chat_log(self, limit=50):
        with self._lock:
            return list(self._chat_log)[-limit:]


class SessionTimeline:
    """Builds a chronological browsing timeline per device."""

    def __init__(self):
        self._events = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.Lock()

    def add_event(self, device_ip, event_type, description, domain="",
                  url="", category="", extra=None):
        """Add a timeline event."""
        event = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "description": description,
            "domain": domain,
            "url": url,
            "category": category,
            "extra": extra or {},
        }

        with self._lock:
            self._events[device_ip].append(event)

    def get_timeline(self, device_ip, limit=50):
        with self._lock:
            return list(self._events.get(device_ip, []))[-limit:]

    def get_all_timelines(self, limit=100):
        """Get merged timeline across all devices."""
        with self._lock:
            all_events = []
            for ip, events in self._events.items():
                for e in events:
                    entry = dict(e)
                    entry["device_ip"] = ip
                    all_events.append(entry)

            all_events.sort(key=lambda x: x["timestamp"])
            return all_events[-limit:]

    def export_text(self, device_ip):
        """Export timeline as readable text."""
        events = self.get_timeline(device_ip, limit=500)
        lines = [f"=== Browsing Timeline for {device_ip} ===\n"]
        for e in events:
            icon = {"DNS": "🔍", "HTTPS": "🔒", "HTTP": "🌐", "SEARCH": "🔎",
                    "DOWNLOAD": "📁", "CHAT": "💬", "ALERT": "🚨"}.get(e["type"], "•")
            lines.append(f"  {e['time']}  {icon} {e['description']}")
        return "\n".join(lines)
