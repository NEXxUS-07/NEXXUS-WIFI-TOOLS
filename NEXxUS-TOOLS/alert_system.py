"""
NetVision — Alert System Module
Real-time alerts for specific sites, keywords, categories, and suspicious activity.
Supports terminal notifications and Telegram push notifications.
"""

import re
import threading
import time
import os
from datetime import datetime
from collections import deque

try:
    import requests as req_lib
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


class AlertRule:
    """A single alert rule."""

    def __init__(self, name, rule_type, pattern, severity="medium", sound=True):
        self.name = name
        self.rule_type = rule_type  # domain, keyword, category, ip, regex
        self.pattern = pattern
        self.severity = severity   # low, medium, high, critical
        self.sound = sound
        self.triggered_count = 0
        self.last_triggered = None

    def matches(self, text):
        text_lower = text.lower()
        if self.rule_type == "domain":
            return self.pattern.lower() in text_lower
        elif self.rule_type == "keyword":
            return self.pattern.lower() in text_lower
        elif self.rule_type == "category":
            return self.pattern.lower() == text_lower
        elif self.rule_type == "regex":
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        elif self.rule_type == "ip":
            return self.pattern == text
        return False


class Alert:
    """A triggered alert."""

    def __init__(self, rule, device_ip, details, domain="", url=""):
        self.timestamp = datetime.now()
        self.rule_name = rule.name
        self.severity = rule.severity
        self.device_ip = device_ip
        self.details = details
        self.domain = domain
        self.url = url

    def to_dict(self):
        return {
            "time": self.timestamp.strftime("%H:%M:%S"),
            "rule": self.rule_name,
            "severity": self.severity,
            "device": self.device_ip,
            "details": self.details,
            "domain": self.domain,
            "url": self.url,
        }


class AlertSystem:
    """Manages alert rules and notifications."""

    def __init__(self, telegram_token=None, telegram_chat_id=None):
        self._rules = []
        self._alerts = deque(maxlen=500)
        self._lock = threading.Lock()
        self._telegram_token = telegram_token
        self._telegram_chat_id = telegram_chat_id
        self._alert_callbacks = []

        # Default rules
        self._setup_default_rules()

    def _setup_default_rules(self):
        """Setup built-in alert rules."""
        # Adult content
        adult_domains = ["pornhub", "xvideos", "xnxx", "xhamster", "redtube",
                         "youporn", "brazzers", "onlyfans", "chaturbate"]
        for d in adult_domains:
            self._rules.append(AlertRule(
                f"Adult: {d}", "domain", d, severity="high", sound=True
            ))

        # Social media
        for d in ["facebook", "instagram", "tiktok", "snapchat", "twitter"]:
            self._rules.append(AlertRule(
                f"Social: {d}", "domain", d, severity="low", sound=False
            ))

        # Banking / Financial
        for d in ["paypal", "banking", "bank.", "chase.com", "wellsfargo",
                   "citibank", "netbanking", "onlinebanking"]:
            self._rules.append(AlertRule(
                f"Banking: {d}", "domain", d, severity="critical", sound=True
            ))

        # Downloads
        self._rules.append(AlertRule(
            "APK Download", "regex", r"\.apk(\?|$)", severity="high"
        ))
        self._rules.append(AlertRule(
            "EXE Download", "regex", r"\.exe(\?|$)", severity="high"
        ))
        self._rules.append(AlertRule(
            "Torrent", "domain", "torrent", severity="medium"
        ))

        # VPN / Privacy
        for d in ["nordvpn", "expressvpn", "protonvpn", "torproject", "tor."]:
            self._rules.append(AlertRule(
                f"VPN/Privacy: {d}", "domain", d, severity="medium"
            ))

        # Dark web indicators
        self._rules.append(AlertRule(
            "Onion/Dark Web", "regex", r"\.onion", severity="critical"
        ))

        # Hacking / Security tools
        for d in ["kali", "metasploit", "exploit-db", "hack"]:
            self._rules.append(AlertRule(
                f"Security: {d}", "keyword", d, severity="high"
            ))

    def add_rule(self, name, rule_type, pattern, severity="medium"):
        """Add a custom alert rule."""
        self._rules.append(AlertRule(name, rule_type, pattern, severity))

    def check(self, device_ip, domain="", url="", search_query="", category=""):
        """Check all rules against the given data. Returns list of triggered alerts."""
        triggered = []

        texts_to_check = [
            ("domain", domain),
            ("url", url),
            ("search", search_query),
            ("category", category),
        ]

        for rule in self._rules:
            for source, text in texts_to_check:
                if text and rule.matches(text):
                    rule.triggered_count += 1
                    rule.last_triggered = datetime.now()

                    alert = Alert(
                        rule=rule,
                        device_ip=device_ip,
                        details=f"[{source}] {text[:80]}",
                        domain=domain,
                        url=url,
                    )

                    with self._lock:
                        self._alerts.append(alert)

                    triggered.append(alert)

                    # Send notification
                    if rule.severity in ("high", "critical"):
                        self._notify(alert)

                    # Callbacks
                    for cb in self._alert_callbacks:
                        try:
                            cb(alert)
                        except Exception:
                            pass

                    break  # Don't trigger same rule multiple times per check

        return triggered

    def _notify(self, alert):
        """Send push notification."""
        # Terminal bell
        if alert.severity == "critical":
            print("\a", end="", flush=True)

        # Telegram
        if self._telegram_token and self._telegram_chat_id and REQUESTS_OK:
            threading.Thread(target=self._send_telegram, args=(alert,), daemon=True).start()

    def _send_telegram(self, alert):
        """Send Telegram notification."""
        try:
            severity_emoji = {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
            emoji = severity_emoji.get(alert.severity, "⚠️")

            msg = (
                f"{emoji} *NetVision Alert*\n\n"
                f"*Rule:* {alert.rule_name}\n"
                f"*Device:* `{alert.device_ip}`\n"
                f"*Details:* {alert.details}\n"
                f"*Time:* {alert.timestamp.strftime('%H:%M:%S')}"
            )

            url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
            req_lib.post(url, json={
                "chat_id": self._telegram_chat_id,
                "text": msg,
                "parse_mode": "Markdown",
            }, timeout=5)
        except Exception:
            pass

    def on_alert(self, callback):
        """Register a callback for alerts."""
        self._alert_callbacks.append(callback)

    def get_alerts(self, limit=50, severity=None):
        """Get recent alerts, optionally filtered by severity."""
        with self._lock:
            alerts = list(self._alerts)
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            return [a.to_dict() for a in alerts[-limit:]]

    def get_stats(self):
        """Get alert statistics."""
        with self._lock:
            counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            for alert in self._alerts:
                counts[alert.severity] = counts.get(alert.severity, 0) + 1
            return {
                "total": len(self._alerts),
                "by_severity": counts,
                "rules_count": len(self._rules),
            }
