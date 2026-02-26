"""
╔══════════════════════════════════════════════════════════════════════╗
║   🔬 Deep App Intelligence — Traffic Pattern Analysis               ║
║                                                                      ║
║   Extracts maximum intelligence from ENCRYPTED traffic:              ║
║     • Detect typing activity (small frequent outbound packets)       ║
║     • Detect media transfers (large packet bursts)                   ║
║     • Detect voice/video calls (sustained UDP streams)               ║
║     • Track app session durations & usage patterns                   ║
║     • Count estimated messages sent/received per app                 ║
║     • Detect notifications from push services                        ║
║     • Real-time per-app activity status                              ║
║                                                                      ║
║   ⚠ Cannot read actual message CONTENT (E2EE encryption).            ║
║   This module analyzes TRAFFIC PATTERNS, not payloads.               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import threading
import time
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter


# ═══════════════════════════════════════════════════════════════════════
# APP SIGNATURES — Domain/IP patterns for each app
# ═══════════════════════════════════════════════════════════════════════

APP_SIGNATURES = {
    "WhatsApp": {
        "domains": [
            "whatsapp.net", "whatsapp.com", "wa.me",
            "web.whatsapp.com", "mmg.whatsapp.net",
            "pps.whatsapp.net", "static.whatsapp.net",
            "media.whatsapp.net", "media-sin6-1.cdn.whatsapp.net",
        ],
        "ip_ranges": ["157.240.", "31.13.", "179.60."],
        "ports": [443, 5222, 5228],
        "icon": "💚",
        "category": "messaging",
        "media_domains": ["mmg.whatsapp.net", "media.whatsapp.net"],
        "call_ports": [3478, 443],  # STUN/TURN for calls
    },
    "Instagram": {
        "domains": [
            "instagram.com", "cdninstagram.com",
            "i.instagram.com", "scontent.cdninstagram.com",
            "edge-chat.instagram.com", "graph.instagram.com",
            "instagram.c10r.facebook.com",
        ],
        "ip_ranges": ["157.240.", "31.13."],
        "ports": [443],
        "icon": "📸",
        "category": "social",
        "media_domains": ["scontent.cdninstagram.com", "cdninstagram.com"],
    },
    "Facebook": {
        "domains": [
            "facebook.com", "fbcdn.net", "fb.com",
            "messenger.com", "m.facebook.com",
            "edge-chat.facebook.com", "star.c10r.facebook.com",
            "mqtt-mini.facebook.com", "graph.facebook.com",
        ],
        "ip_ranges": ["157.240.", "31.13."],
        "ports": [443],
        "icon": "📘",
        "category": "social",
        "media_domains": ["fbcdn.net", "scontent.fbcdn.net"],
    },
    "Messenger": {
        "domains": [
            "messenger.com", "www.messenger.com",
            "edge-chat.messenger.com", "mqtt-mini.facebook.com",
            "rupload.facebook.com",
        ],
        "ip_ranges": ["157.240.", "31.13."],
        "ports": [443],
        "icon": "💬",
        "category": "messaging",
    },
    "Telegram": {
        "domains": [
            "telegram.org", "t.me", "web.telegram.org",
            "core.telegram.org", "api.telegram.org",
        ],
        "ip_ranges": ["149.154.", "91.108."],
        "ports": [443, 80, 8443],
        "icon": "✈️",
        "category": "messaging",
        "media_domains": ["cdn1.telegram-cdn.org", "cdn4.telegram-cdn.org"],
    },
    "Discord": {
        "domains": [
            "discord.com", "discordapp.com", "discord.gg",
            "cdn.discordapp.com", "gateway.discord.gg",
            "media.discordapp.net", "images-ext-1.discordapp.net",
        ],
        "ip_ranges": ["162.159."],
        "ports": [443],
        "icon": "🎮",
        "category": "messaging",
        "media_domains": ["cdn.discordapp.com", "media.discordapp.net"],
    },
    "Snapchat": {
        "domains": [
            "snapchat.com", "snap-dev.net",
            "sc-cdn.net", "snap.com",
            "sc-analytics.appspot.com", "cf-st.sc-cdn.net",
            "bolt.sc-cdn.net",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "👻",
        "category": "social",
        "media_domains": ["cf-st.sc-cdn.net", "bolt.sc-cdn.net"],
    },
    "TikTok": {
        "domains": [
            "tiktok.com", "tiktokv.com",
            "musical.ly", "isnssdk.com",
            "bytedance.com", "byteimg.com",
            "tiktokcdn.com", "byteoversea.com",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "🎵",
        "category": "social",
        "media_domains": ["tiktokcdn.com", "byteimg.com"],
    },
    "YouTube": {
        "domains": [
            "youtube.com", "youtu.be", "ytimg.com",
            "googlevideo.com", "yt3.ggpht.com",
            "youtube-ui.l.google.com",
        ],
        "ip_ranges": ["142.250.", "172.217.", "216.58."],
        "ports": [443],
        "icon": "🎬",
        "category": "video",
        "media_domains": ["googlevideo.com"],
    },
    "Netflix": {
        "domains": [
            "netflix.com", "nflxvideo.net",
            "nflxso.net", "nflximg.net",
            "nflxext.com",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "🎬",
        "category": "video",
        "media_domains": ["nflxvideo.net"],
    },
    "Spotify": {
        "domains": [
            "spotify.com", "scdn.co",
            "audio-ak-spotify-com.akamaized.net",
            "heads-ak-spotify-com.akamaized.net",
        ],
        "ip_ranges": [],
        "ports": [443, 4070],
        "icon": "🎵",
        "category": "music",
        "media_domains": ["audio-ak-spotify-com.akamaized.net"],
    },
    "Twitter/X": {
        "domains": [
            "twitter.com", "x.com", "t.co",
            "twimg.com", "pbs.twimg.com",
            "abs.twimg.com", "api.twitter.com",
        ],
        "ip_ranges": ["104.244."],
        "ports": [443],
        "icon": "🐦",
        "category": "social",
    },
    "Signal": {
        "domains": [
            "signal.org", "whispersystems.org",
            "signal.art", "updates.signal.org",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "🔒",
        "category": "messaging",
    },
    "Reddit": {
        "domains": [
            "reddit.com", "redd.it", "redditmedia.com",
            "redditenhancer.com",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "📱",
        "category": "social",
    },
    "Google": {
        "domains": [
            "google.com", "googleapis.com", "gstatic.com",
            "google.co.in", "googleusercontent.com",
        ],
        "ip_ranges": ["142.250.", "172.217.", "216.58."],
        "ports": [443],
        "icon": "🔍",
        "category": "search",
    },
    "Amazon": {
        "domains": [
            "amazon.com", "amazon.in", "amazon.co.uk",
            "media-amazon.com", "ssl-images-amazon.com",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "🛒",
        "category": "shopping",
    },
    "Gmail": {
        "domains": [
            "mail.google.com", "gmail.com",
            "googlemail.com",
        ],
        "ip_ranges": [],
        "ports": [443, 993, 995],
        "icon": "📧",
        "category": "email",
    },
    "Zoom": {
        "domains": [
            "zoom.us", "zoom.com",
            "zoomgov.com",
        ],
        "ip_ranges": [],
        "ports": [443, 8801, 8802],
        "icon": "📹",
        "category": "call",
    },
    "Microsoft Teams": {
        "domains": [
            "teams.microsoft.com", "teams.live.com",
            "statics.teams.cdn.office.net",
        ],
        "ip_ranges": [],
        "ports": [443],
        "icon": "💼",
        "category": "call",
    },
}


# ═══════════════════════════════════════════════════════════════════════
# PACKET PATTERN THRESHOLDS
# ═══════════════════════════════════════════════════════════════════════

# Packet size thresholds for activity detection
TYPING_PKT_SIZE_MAX = 200       # Typing packets are small
MSG_PKT_SIZE_MIN = 100          # Message packets
MSG_PKT_SIZE_MAX = 1500
MEDIA_PKT_SIZE_MIN = 5000       # Media/image packets are large
CALL_PKT_SIZE_MIN = 100         # VoIP packets
CALL_PKT_SIZE_MAX = 1500
CALL_FREQ_MIN = 20              # Min packets/sec for voice call
VIDEO_CALL_BPS_MIN = 50000      # 50 KB/s = probably video call
TYPING_BURST_WINDOW = 3         # seconds
TYPING_BURST_MIN_PKTS = 5       # min packets in burst to = typing


class AppSession:
    """Tracks a single app usage session."""

    def __init__(self, app_name, device_ip):
        self.app_name = app_name
        self.device_ip = device_ip
        self.start_time = datetime.now()
        self.last_seen = datetime.now()
        self.is_active = True

        # Packet tracking
        self.total_packets = 0
        self.total_bytes = 0
        self.outbound_packets = 0
        self.inbound_packets = 0
        self.outbound_bytes = 0
        self.inbound_bytes = 0

        # Activity detection
        self.estimated_messages_sent = 0
        self.estimated_messages_received = 0
        self.media_transfers = 0
        self.media_bytes = 0
        self.is_typing = False
        self.is_in_call = False
        self.is_video_call = False
        self.call_duration = 0  # seconds

        # Packet timing for burst detection
        self._recent_outbound = deque(maxlen=100)  # (timestamp, size) for burst detection
        self._recent_inbound = deque(maxlen=100)
        self._call_start = None

        # Notification tracking
        self.notifications_received = 0

        # Activity log
        self.activity_log = deque(maxlen=200)

    @property
    def duration(self):
        return (self.last_seen - self.start_time).total_seconds()

    @property
    def duration_str(self):
        secs = int(self.duration)
        if secs < 60:
            return f"{secs}s"
        elif secs < 3600:
            return f"{secs // 60}m {secs % 60}s"
        else:
            return f"{secs // 3600}h {(secs % 3600) // 60}m"

    def to_dict(self):
        return {
            "app": self.app_name,
            "device": self.device_ip,
            "start": self.start_time.strftime("%H:%M:%S"),
            "duration": self.duration_str,
            "active": self.is_active,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "msgs_sent": self.estimated_messages_sent,
            "msgs_received": self.estimated_messages_received,
            "media_transfers": self.media_transfers,
            "is_typing": self.is_typing,
            "is_in_call": self.is_in_call,
            "is_video_call": self.is_video_call,
            "call_duration": self.call_duration,
            "notifications": self.notifications_received,
        }


class DeepAppIntel:
    """
    Advanced traffic pattern analysis for encrypted app traffic.

    Analyzes packet sizes, frequencies, and timing patterns to detect:
    - Which apps are in use and for how long
    - When someone is actively typing/chatting
    - When media (photos/videos) are being sent/received
    - When voice/video calls are happening
    - Estimated message counts per app
    - Push notification events
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Per-device, per-app sessions
        # device_ip -> app_name -> AppSession
        self._sessions = defaultdict(dict)

        # Domain -> app mapping cache
        self._domain_cache = {}

        # Per-device real-time activity
        self._device_activity = defaultdict(lambda: {
            "current_apps": set(),
            "typing_in": None,
            "in_call": None,
            "last_notification": None,
        })

        # Global event feed
        self._events = deque(maxlen=500)

        # Packet rate tracking per device+app
        self._packet_windows = defaultdict(lambda: deque(maxlen=200))

        # Build domain lookup
        self._build_domain_cache()

        # Start activity decay thread
        self._running = True
        threading.Thread(target=self._activity_decay_loop, daemon=True).start()

    def stop(self):
        self._running = False

    def _build_domain_cache(self):
        """Pre-build domain -> app mapping for fast lookup."""
        for app_name, sig in APP_SIGNATURES.items():
            for domain in sig["domains"]:
                self._domain_cache[domain] = app_name

    def identify_app(self, domain, dst_ip="", dst_port=443):
        """Identify which app a domain/IP belongs to."""
        if not domain:
            return None

        domain_lower = domain.lower()

        # Direct domain match
        if domain_lower in self._domain_cache:
            return self._domain_cache[domain_lower]

        # Substring match
        for app_name, sig in APP_SIGNATURES.items():
            for d in sig["domains"]:
                if d in domain_lower or domain_lower.endswith("." + d):
                    self._domain_cache[domain_lower] = app_name
                    return app_name

        # IP range match
        if dst_ip:
            for app_name, sig in APP_SIGNATURES.items():
                for ip_range in sig.get("ip_ranges", []):
                    if dst_ip.startswith(ip_range):
                        return app_name

        return None

    def process_packet(self, device_ip, domain="", dst_ip="", dst_port=443,
                       pkt_size=0, direction="OUT", proto="TCP",
                       url="", content_type=""):
        """
        Process a packet and update app intelligence.

        Args:
            device_ip: Target device IP
            domain: Domain name (from DNS/SNI)
            dst_ip: Destination IP
            dst_port: Destination port
            pkt_size: Packet size in bytes
            direction: "OUT" (from device) or "IN" (to device)
            proto: Protocol (TCP/UDP/QUIC)
            url: Full URL if available
            content_type: HTTP Content-Type if available
        """
        app_name = self.identify_app(domain, dst_ip, dst_port)
        if not app_name:
            return None

        now = datetime.now()

        with self._lock:
            # Get or create session
            if app_name not in self._sessions[device_ip]:
                self._sessions[device_ip][app_name] = AppSession(app_name, device_ip)
                self._log_event(device_ip, app_name, "APP_OPEN",
                               f"Started using {app_name}")

            session = self._sessions[device_ip][app_name]
            session.last_seen = now
            session.is_active = True
            session.total_packets += 1
            session.total_bytes += pkt_size

            # Track direction
            if direction == "OUT":
                session.outbound_packets += 1
                session.outbound_bytes += pkt_size
                session._recent_outbound.append((now, pkt_size))
            else:
                session.inbound_packets += 1
                session.inbound_bytes += pkt_size
                session._recent_inbound.append((now, pkt_size))

            # Update device activity
            self._device_activity[device_ip]["current_apps"].add(app_name)

            # Track packet rate
            key = f"{device_ip}:{app_name}"
            self._packet_windows[key].append((now, pkt_size, direction, proto))

            # ─── ACTIVITY DETECTION ──────────────────────

            sig = APP_SIGNATURES.get(app_name, {})
            is_messaging = sig.get("category") in ("messaging", "social")

            # 1. TYPING DETECTION (small frequent outbound packets)
            if is_messaging and direction == "OUT" and pkt_size < TYPING_PKT_SIZE_MAX:
                recent = [t for t, s in session._recent_outbound
                          if (now - t).total_seconds() < TYPING_BURST_WINDOW]
                if len(recent) >= TYPING_BURST_MIN_PKTS:
                    if not session.is_typing:
                        session.is_typing = True
                        self._device_activity[device_ip]["typing_in"] = app_name
                        self._log_event(device_ip, app_name, "TYPING",
                                       f"Typing in {app_name}...")

            # 2. MESSAGE DETECTION
            if is_messaging:
                # Outbound message (medium-sized outbound packet after typing burst)
                if direction == "OUT" and MSG_PKT_SIZE_MIN < pkt_size < MSG_PKT_SIZE_MAX:
                    if session.is_typing or pkt_size > 300:
                        session.estimated_messages_sent += 1
                        session.is_typing = False
                        self._device_activity[device_ip]["typing_in"] = None
                        if session.estimated_messages_sent % 3 == 1:  # Don't spam events
                            self._log_event(device_ip, app_name, "MSG_SENT",
                                           f"Sent message #{session.estimated_messages_sent} in {app_name}")

                # Inbound message (medium packet from server)
                if direction == "IN" and MSG_PKT_SIZE_MIN < pkt_size < MSG_PKT_SIZE_MAX:
                    session.estimated_messages_received += 1
                    if session.estimated_messages_received % 3 == 1:
                        self._log_event(device_ip, app_name, "MSG_RECV",
                                       f"Received message #{session.estimated_messages_received} in {app_name}")

            # 3. MEDIA TRANSFER DETECTION (large packets)
            if pkt_size > MEDIA_PKT_SIZE_MIN:
                media_domains = sig.get("media_domains", [])
                is_media_domain = any(md in (domain or "").lower() for md in media_domains)

                if is_media_domain or pkt_size > 10000:
                    session.media_transfers += 1
                    session.media_bytes += pkt_size

                    if direction == "OUT":
                        media_type = "photo/video" if pkt_size > 50000 else "image"
                        if session.media_transfers % 2 == 1:
                            self._log_event(device_ip, app_name, "MEDIA_SEND",
                                           f"Sending {media_type} in {app_name} "
                                           f"({self._fmt_bytes(pkt_size)})")
                    else:
                        if session.media_transfers % 2 == 1:
                            self._log_event(device_ip, app_name, "MEDIA_RECV",
                                           f"Receiving media in {app_name} "
                                           f"({self._fmt_bytes(pkt_size)})")

            # 4. CALL DETECTION (sustained UDP streams)
            if proto in ("UDP", "QUIC") and sig.get("category") in ("messaging", "call"):
                window = list(self._packet_windows[key])
                recent_udp = [
                    (t, s) for t, s, d, p in window
                    if p in ("UDP", "QUIC") and (now - t).total_seconds() < 5
                ]

                if len(recent_udp) > CALL_FREQ_MIN:
                    total_bps = sum(s for _, s in recent_udp) / 5
                    if not session.is_in_call:
                        session.is_in_call = True
                        session._call_start = now
                        session.is_video_call = total_bps > VIDEO_CALL_BPS_MIN
                        call_type = "video call" if session.is_video_call else "voice call"
                        self._device_activity[device_ip]["in_call"] = app_name
                        self._log_event(device_ip, app_name, "CALL_START",
                                       f"Started {call_type} on {app_name}")
                    elif session._call_start:
                        session.call_duration = (now - session._call_start).total_seconds()
                        # Update call type
                        session.is_video_call = total_bps > VIDEO_CALL_BPS_MIN

            # 5. NOTIFICATION DETECTION (small inbound push packets)
            if direction == "IN" and pkt_size < 500:
                push_domains = [
                    "push.apple.com", "mtalk.google.com",
                    "fcm.googleapis.com", "firebase",
                    "push", "notify", "mqtt",
                ]
                if any(pd in (domain or "").lower() for pd in push_domains):
                    session.notifications_received += 1
                    self._device_activity[device_ip]["last_notification"] = {
                        "app": app_name,
                        "time": now.strftime("%H:%M:%S"),
                    }
                    self._log_event(device_ip, app_name, "NOTIFICATION",
                                   f"Push notification for {app_name}")

        return app_name

    def _log_event(self, device_ip, app_name, event_type, description):
        """Log an intelligence event."""
        sig = APP_SIGNATURES.get(app_name, {})
        icon = sig.get("icon", "📱")

        self._events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "device": device_ip,
            "app": app_name,
            "icon": icon,
            "type": event_type,
            "description": description,
        })

    def _activity_decay_loop(self):
        """Mark sessions as inactive if no packets for 30s. End calls after silence."""
        while self._running:
            try:
                now = datetime.now()
                with self._lock:
                    for device_ip, apps in self._sessions.items():
                        for app_name, session in apps.items():
                            idle_time = (now - session.last_seen).total_seconds()

                            # Typing timeout (5 seconds)
                            if session.is_typing and idle_time > 5:
                                session.is_typing = False
                                if self._device_activity[device_ip].get("typing_in") == app_name:
                                    self._device_activity[device_ip]["typing_in"] = None

                            # Call end detection (10 seconds no UDP)
                            if session.is_in_call and idle_time > 10:
                                if session._call_start:
                                    session.call_duration = (now - session._call_start).total_seconds()
                                call_type = "Video" if session.is_video_call else "Voice"
                                self._log_event(device_ip, app_name, "CALL_END",
                                               f"{call_type} call ended on {app_name} "
                                               f"({int(session.call_duration)}s)")
                                session.is_in_call = False
                                session.is_video_call = False
                                session._call_start = None
                                if self._device_activity[device_ip].get("in_call") == app_name:
                                    self._device_activity[device_ip]["in_call"] = None

                            # Session inactive (30 seconds)
                            if session.is_active and idle_time > 30:
                                session.is_active = False
                                self._device_activity[device_ip]["current_apps"].discard(app_name)
                                if session.total_packets > 10:
                                    self._log_event(device_ip, app_name, "APP_CLOSE",
                                                   f"Stopped using {app_name} "
                                                   f"(was active for {session.duration_str})")
            except Exception:
                pass

            time.sleep(3)

    # ═══════════════════════════════════════════════════════════════════
    # PUBLIC API — Get intelligence data
    # ═══════════════════════════════════════════════════════════════════

    def get_active_apps(self, device_ip):
        """Get all currently active apps for a device."""
        with self._lock:
            result = {}
            for app_name, session in self._sessions.get(device_ip, {}).items():
                if session.is_active:
                    sig = APP_SIGNATURES.get(app_name, {})
                    status = "📱 Active"
                    if session.is_typing:
                        status = "⌨️ TYPING..."
                    elif session.is_in_call:
                        call_type = "📹" if session.is_video_call else "📞"
                        dur = int(session.call_duration)
                        status = f"{call_type} IN CALL ({dur}s)"
                    elif session.media_transfers > 0 and (
                        datetime.now() - session.last_seen
                    ).total_seconds() < 5:
                        status = "📸 Sending/receiving media"

                    result[app_name] = {
                        "icon": sig.get("icon", "📱"),
                        "status": status,
                        "duration": session.duration_str,
                        "msgs_sent": session.estimated_messages_sent,
                        "msgs_recv": session.estimated_messages_received,
                        "media": session.media_transfers,
                        "bytes": session.total_bytes,
                        "is_typing": session.is_typing,
                        "is_call": session.is_in_call,
                        "is_video": session.is_video_call,
                    }
            return result

    def get_all_sessions(self, device_ip):
        """Get all sessions (active + inactive) for a device."""
        with self._lock:
            sessions = self._sessions.get(device_ip, {})
            return {
                name: s.to_dict()
                for name, s in sorted(
                    sessions.items(),
                    key=lambda x: x[1].last_seen,
                    reverse=True,
                )
            }

    def get_device_status(self, device_ip):
        """Get real-time status summary for a device."""
        with self._lock:
            activity = self._device_activity.get(device_ip, {})
            sessions = self._sessions.get(device_ip, {})

            active_apps = [
                name for name, s in sessions.items()
                if s.is_active
            ]

            typing_in = activity.get("typing_in")
            in_call = activity.get("in_call")

            # Build status string
            parts = []
            if in_call:
                call_session = sessions.get(in_call)
                if call_session and call_session.is_video_call:
                    parts.append(f"📹 Video call on {in_call}")
                else:
                    parts.append(f"📞 Voice call on {in_call}")
            if typing_in:
                parts.append(f"⌨️ Typing in {typing_in}")
            if not parts and active_apps:
                parts.append(f"Using: {', '.join(active_apps[:3])}")
            if not parts:
                parts.append("💤 Idle")

            total_msgs = sum(
                s.estimated_messages_sent + s.estimated_messages_received
                for s in sessions.values()
            )

            return {
                "status": " | ".join(parts),
                "active_apps": active_apps,
                "typing_in": typing_in,
                "in_call": in_call,
                "total_messages": total_msgs,
                "total_media": sum(s.media_transfers for s in sessions.values()),
                "total_bytes": sum(s.total_bytes for s in sessions.values()),
            }

    def get_events(self, limit=50, device_ip=None):
        """Get intelligence event feed."""
        with self._lock:
            events = list(self._events)
            if device_ip:
                events = [e for e in events if e["device"] == device_ip]
            return events[-limit:]

    def get_message_stats(self, device_ip):
        """Get per-app message statistics."""
        with self._lock:
            stats = {}
            for app_name, session in self._sessions.get(device_ip, {}).items():
                if session.estimated_messages_sent > 0 or session.estimated_messages_received > 0:
                    sig = APP_SIGNATURES.get(app_name, {})
                    stats[app_name] = {
                        "icon": sig.get("icon", "📱"),
                        "sent": session.estimated_messages_sent,
                        "received": session.estimated_messages_received,
                        "total": session.estimated_messages_sent + session.estimated_messages_received,
                        "media": session.media_transfers,
                        "media_bytes": session.media_bytes,
                    }
            return stats

    def get_call_info(self, device_ip):
        """Get information about active/past calls."""
        with self._lock:
            calls = []
            for app_name, session in self._sessions.get(device_ip, {}).items():
                if session.is_in_call or session.call_duration > 0:
                    calls.append({
                        "app": app_name,
                        "icon": APP_SIGNATURES.get(app_name, {}).get("icon", "📱"),
                        "active": session.is_in_call,
                        "video": session.is_video_call,
                        "duration": int(session.call_duration),
                    })
            return calls

    def get_summary(self, device_ip):
        """Generate a text summary of what the device is doing."""
        with self._lock:
            sessions = self._sessions.get(device_ip, {})
            if not sessions:
                return "No app activity detected yet."

            lines = []
            active = [(n, s) for n, s in sessions.items() if s.is_active]
            inactive = [(n, s) for n, s in sessions.items() if not s.is_active]

            for name, s in active:
                sig = APP_SIGNATURES.get(name, {})
                icon = sig.get("icon", "📱")
                line = f"{icon} {name}: active for {s.duration_str}"

                details = []
                if s.is_in_call:
                    call_type = "video call" if s.is_video_call else "voice call"
                    details.append(f"IN {call_type} ({int(s.call_duration)}s)")
                if s.is_typing:
                    details.append("TYPING NOW")
                if s.estimated_messages_sent > 0:
                    details.append(f"{s.estimated_messages_sent} msgs sent")
                if s.estimated_messages_received > 0:
                    details.append(f"{s.estimated_messages_received} msgs received")
                if s.media_transfers > 0:
                    details.append(f"{s.media_transfers} media sent/received")

                if details:
                    line += f" — {', '.join(details)}"
                lines.append(line)

            return "\n".join(lines) if lines else "No active apps right now"

    @staticmethod
    def _fmt_bytes(b):
        if b < 1024:
            return f"{b}B"
        elif b < 1048576:
            return f"{b/1024:.1f}KB"
        else:
            return f"{b/1048576:.1f}MB"
