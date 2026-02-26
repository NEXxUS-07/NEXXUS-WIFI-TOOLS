"""
NetVision — Speed Monitor Module
Monitors bandwidth usage per device by tracking network traffic.
"""

import threading
import time
import subprocess
import re
from collections import defaultdict
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class SpeedMonitor:
    """
    Monitors network speed (upload/download) for devices.
    Uses iptables-based traffic accounting or /proc/net stats.
    """

    def __init__(self, interface=None):
        self.interface = interface
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        # Per-device traffic counters: IP -> {"bytes_in": int, "bytes_out": int}
        self._device_counters = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0,
            "prev_in": 0, "prev_out": 0,
            "speed_in": 0.0, "speed_out": 0.0,
            "total_in": 0, "total_out": 0,
        })

        # Global interface counters
        self._prev_bytes_sent = 0
        self._prev_bytes_recv = 0
        self._global_speed_up = 0.0
        self._global_speed_down = 0.0
        self._total_sent = 0
        self._total_recv = 0

        # History for sparklines
        self._speed_history_up = []
        self._speed_history_down = []
        self._max_history = 60

    def start(self, interval=2):
        """Start monitoring in background thread."""
        self._running = True
        self._init_counters()
        self._thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop monitoring."""
        self._running = False

    def _init_counters(self):
        """Initialize baseline counters."""
        if PSUTIL_AVAILABLE:
            counters = psutil.net_io_counters(pernic=True)
            if self.interface and self.interface in counters:
                nic = counters[self.interface]
            else:
                nic = psutil.net_io_counters()

            self._prev_bytes_sent = nic.bytes_sent
            self._prev_bytes_recv = nic.bytes_recv

    def _monitor_loop(self, interval):
        """Main monitoring loop."""
        while self._running:
            try:
                self._update_global_speed(interval)
                self._update_device_speeds(interval)
            except Exception:
                pass
            time.sleep(interval)

    def _update_global_speed(self, interval):
        """Update global interface speed."""
        if not PSUTIL_AVAILABLE:
            return

        counters = psutil.net_io_counters(pernic=True)
        if self.interface and self.interface in counters:
            nic = counters[self.interface]
        else:
            nic = psutil.net_io_counters()

        bytes_sent = nic.bytes_sent
        bytes_recv = nic.bytes_recv

        with self._lock:
            if self._prev_bytes_sent > 0:
                self._global_speed_up = (bytes_sent - self._prev_bytes_sent) / interval / 1024  # KB/s
                self._global_speed_down = (bytes_recv - self._prev_bytes_recv) / interval / 1024  # KB/s
                self._total_sent = bytes_sent
                self._total_recv = bytes_recv

                # History
                self._speed_history_up.append(self._global_speed_up)
                self._speed_history_down.append(self._global_speed_down)
                if len(self._speed_history_up) > self._max_history:
                    self._speed_history_up.pop(0)
                    self._speed_history_down.pop(0)

            self._prev_bytes_sent = bytes_sent
            self._prev_bytes_recv = bytes_recv

    def _update_device_speeds(self, interval):
        """Update per-device speed estimates using /proc/net/nf_conntrack or iptables."""
        device_traffic = self._read_conntrack()

        with self._lock:
            for ip, data in device_traffic.items():
                counter = self._device_counters[ip]
                if counter["prev_in"] > 0:
                    counter["speed_in"] = max(0, (data["bytes_in"] - counter["prev_in"])) / interval / 1024
                    counter["speed_out"] = max(0, (data["bytes_out"] - counter["prev_out"])) / interval / 1024

                counter["prev_in"] = data["bytes_in"]
                counter["prev_out"] = data["bytes_out"]
                counter["total_in"] = data["bytes_in"]
                counter["total_out"] = data["bytes_out"]

    def _read_conntrack(self):
        """Read connection tracking data from /proc/net/nf_conntrack."""
        traffic = defaultdict(lambda: {"bytes_in": 0, "bytes_out": 0})

        # Try /proc/net/nf_conntrack
        try:
            with open("/proc/net/nf_conntrack", "r") as f:
                for line in f:
                    try:
                        src_match = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
                        bytes_match = re.findall(r"bytes=(\d+)", line)
                        if src_match and bytes_match:
                            src_ip = src_match.group(1)
                            if len(bytes_match) >= 2:
                                traffic[src_ip]["bytes_out"] += int(bytes_match[0])
                                traffic[src_ip]["bytes_in"] += int(bytes_match[1])
                            elif len(bytes_match) == 1:
                                traffic[src_ip]["bytes_out"] += int(bytes_match[0])
                    except (ValueError, IndexError):
                        continue
        except (FileNotFoundError, PermissionError):
            pass

        # Fallback: try conntrack command
        if not traffic:
            try:
                result = subprocess.run(
                    ["conntrack", "-L", "-o", "extended"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    try:
                        src_match = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
                        bytes_match = re.findall(r"bytes=(\d+)", line)
                        if src_match and bytes_match:
                            src_ip = src_match.group(1)
                            if len(bytes_match) >= 2:
                                traffic[src_ip]["bytes_out"] += int(bytes_match[0])
                                traffic[src_ip]["bytes_in"] += int(bytes_match[1])
                    except (ValueError, IndexError):
                        continue
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return traffic

    def get_device_speed(self, ip):
        """Get speed data for a specific device."""
        with self._lock:
            counter = self._device_counters.get(ip)
            if counter:
                return {
                    "speed_in": counter["speed_in"],
                    "speed_out": counter["speed_out"],
                    "total_in": counter["total_in"],
                    "total_out": counter["total_out"],
                }
            return {"speed_in": 0.0, "speed_out": 0.0, "total_in": 0, "total_out": 0}

    def get_global_speed(self):
        """Get global interface speed."""
        with self._lock:
            return {
                "speed_up": self._global_speed_up,
                "speed_down": self._global_speed_down,
                "total_sent": self._total_sent,
                "total_recv": self._total_recv,
                "history_up": list(self._speed_history_up),
                "history_down": list(self._speed_history_down),
            }

    def get_speed_sparkline(self, history, width=20):
        """Generate a sparkline string from speed history."""
        if not history:
            return "▁" * width

        # Take last `width` values
        data = history[-width:]

        # Pad with zeros if not enough data
        while len(data) < width:
            data.insert(0, 0)

        max_val = max(data) if max(data) > 0 else 1
        blocks = "▁▂▃▄▅▆▇█"

        sparkline = ""
        for val in data:
            idx = int((val / max_val) * (len(blocks) - 1))
            sparkline += blocks[idx]

        return sparkline

    @staticmethod
    def format_bytes(bytes_val):
        """Format bytes to human readable string."""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def format_speed(kbps):
        """Format KB/s to human readable speed."""
        if kbps < 1:
            return f"{kbps * 1024:.0f} B/s"
        elif kbps < 1024:
            return f"{kbps:.1f} KB/s"
        else:
            return f"{kbps / 1024:.2f} MB/s"
