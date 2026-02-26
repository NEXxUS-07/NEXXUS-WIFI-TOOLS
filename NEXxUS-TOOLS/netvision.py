"""
╔══════════════════════════════════════════════════════════════════════╗
║         N E X X U S   T O O L S  —  WiFi Cyber Arsenal             ║
║                    Author: kaushik                                  ║
║            https://github.com/NEXxUS-07                              ║
╚══════════════════════════════════════════════════════════════════════╝

  Offensive WiFi toolkit for authorized penetration testing.
  Features: ARP Spoofing, WiFi Kill, Deauth, DNS Spoof,
            Packet Sniffing, MITM, Captive Portal & more.

  ⚠  Requires: sudo / root privileges

Usage:
  sudo python3 netvision.py                # Interactive attack menu
  sudo python3 netvision.py --dashboard    # Full dashboard
  sudo python3 netvision.py --spy          # WiFi spy only
  sudo python3 netvision.py --kill         # WiFi Kill mode
  sudo python3 netvision.py -i wlan0       # Specify interface
"""

import sys
import os
import signal
import argparse
import threading
import time
import random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.columns import Columns
    from rich.align import Align
    from rich.box import HEAVY, ROUNDED, DOUBLE, SIMPLE, MINIMAL, HEAVY_EDGE, SQUARE
    from rich.style import Style
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Error: 'rich' library is required. Install with: pip install rich")
    sys.exit(1)

from scanner import NetworkScanner
from speed_monitor import SpeedMonitor
from traffic_analyzer import TrafficAnalyzer
from geo_mapper import GeoMapper
from wifi_spy import WiFiActivityMonitor
from wifi_blocker import WiFiBlocker
from config import COLORS, SCAN_INTERVAL, SPEED_INTERVAL, TRAFFIC_INTERVAL

import select
import sys
import termios
import tty


# ═══════════════════════════════════════════════════════════════════════
# HACKER UI CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

GLITCH_CHARS = "░▒▓█▀▄▌▐│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌"
MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノ"
SCAN_ANIM = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Hacker color palette
CYBER_GREEN = "bright_green"
CYBER_RED = "bright_red"
CYBER_CYAN = "bright_cyan"
CYBER_YELLOW = "bright_yellow"
CYBER_MAGENTA = "bright_magenta"
NEON_GREEN = "green"
MATRIX_GREEN = "green"
GHOST_DIM = "dim green"
TERMINAL_BG = "on grey3"

VERSION = "5.0"
AUTHOR = "kaushik"
TOOL_NAME = "NEXXUS TOOLS"

SKULL_ART = """
⢿⢿⢿⢿⢿⢿⢿⡁⠹⠋⠋⠋⠋⠿⣿⣿⣿⣿⣿⣿⠿⠷⠶⠾⠿⠻⣿⠻⡦⠙⠻⣿
⣿⣿⠿⣿⠏⠀⠀⠀⠀⠈⣿⠙⠽⠜⡇⠽⠀⠀⠀⠀⠙⠿⣿⠻⠀⠿
⠐⠋⠿⣿⡷⡤⠀⠀⠀⠰⠿⠿⡷⠶⣿⠿⠇⠻⡷⡲⡲⡶⣿⣿⠿⠙⡶⢮
⡤⠀⠀⠋⠻⠇⠿⠿⣯⡆⣿⠻⣿⠿⠿⢮⠵⠼⠿⠙⠉⠀⠈⣣⣿
⣿⣿⡗⠀⠀⠀⠀⠠⠭⡩⠉⠩⣥⠤⠬⡤⡶⠒⠀⠀⠀⠀⠰⣿⣿
⣿⣿⠽⡅⠀⠀⠀⠿⣿⡦⣿⣧⡑⣿⣿⡇⣿⣿⡇⠀⠀⠀⠀⣿⡇⠃
⣿⣿⣿⡷⠻⡦⠀⠈⠉⠉⠋⠋⠘⠋⠋⠋⠙⠋⠁⠀⠀⠀⠀⣿⡇⠸
⠞⣿⣿⣿⡷⠽⡷⡖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⣿⠈
⡦⡅⠋⠿⠿⣿⣿⡷⠽⠧⠀⠀⡶⡸⡇⣿⠸⣧⠀⠀⠀⠀⠸⠿⡆
⣿⣿⣿⡷⢮⢭⡩⠋⠻⠿⣿⡷⡶⡶⠶⡁⡩⠀⠀⠁⠤⠺⣿⣿⠽⡇
"""

NEXXUS_BANNER = r"""
 _   _ _______  __      _   _ ____    _____ ___   ___  _     ____  
| \ | | ____\ \/ /__  _| | | / ___|  |_   _/ _ \ / _ \| |   / ___| 
|  \| |  _|  \  / \ \/ / | | \___ \    | || | | | | | | |   \___ \ 
| |\  | |___ /  \  >  <| |_| |___) |   | || |_| | |_| | |___ ___) |
|_| \_|_____/_/\_\/_/\_\\___/|____/    |_| \___/ \___/|_____|____/ 
"""


def glitch_text(length=8):
    """Generate random glitch characters."""
    return "".join(random.choice(GLITCH_CHARS) for _ in range(length))


def matrix_rain(width=30):
    """Generate a matrix-style rain line."""
    return "".join(random.choice(MATRIX_CHARS) if random.random() > 0.7 else " " for _ in range(width))


class NetVisionDashboard:
    """Main terminal dashboard — GHOST PROTOCOL hacker UI."""

    def __init__(self, interface=None, mode="dashboard"):
        self.console = Console(highlight=False)
        self.mode = mode
        self._running = True
        self._start_time = datetime.now()
        self._spy_active = False
        self._frame = 0  # Animation frame counter

        # Geo tracking thread
        self._geo_thread = None
        self._geo_locations = {}
        self._geo_lock = threading.Lock()

        # WiFi Kill state
        self._wifi_kill_active = False
        self._wifi_kill_count = 0
        self._wifi_blocker = None
        self._kill_lock = threading.Lock()

        # Boot sequence
        self._hacker_boot(interface)

    def _hacker_boot(self, interface):
        """NEXXUS TOOLS cyberpunk boot sequence."""

        # Skull art + branding
        self.console.print(f"[bright_red]{SKULL_ART}[/]")
        self.console.print(f"[bold bright_cyan]{NEXXUS_BANNER}[/]")
        self.console.print(f"[dim bright_cyan]{'=' * 58}[/]")
        self.console.print(f"[bold bright_green]  ☠  NEXXUS TOOLS v{VERSION} — WiFi Cyber Arsenal  ☠[/]")
        self.console.print(f"[dim green]  Author: [bold bright_cyan]{AUTHOR}[/][dim green]  |  github.com/{AUTHOR}/nexxus-tools[/]")
        self.console.print(f"[dim green]  ⚠  For authorized penetration testing only![/]")
        self.console.print(f"[dim bright_cyan]{'=' * 58}[/]")
        self.console.print()

        # Init with glitch effect
        steps = [
            ("SYS", "Initializing kernel modules...", "bright_green"),
            ("NET", "Detecting network interface...", "bright_cyan"),
            ("ARP", "Loading ARP discovery engine...", "bright_yellow"),
            ("DNS", "Configuring name resolution...", "bright_magenta"),
            ("SPY", "Arming packet interceptors...", "bright_red"),
        ]

        for tag, msg, color in steps:
            glitch = glitch_text(4)
            self.console.print(f"  [dim green]{glitch}[/] [{color}][{tag}][/] {msg}")
            time.sleep(0.15)

        self.scanner = NetworkScanner(interface=interface)
        self.speed_monitor = SpeedMonitor(interface=self.scanner.interface)
        self.traffic_analyzer = TrafficAnalyzer(interface=self.scanner.interface)
        self.geo_mapper = GeoMapper()
        self.spy = WiFiActivityMonitor(
            interface=self.scanner.interface,
            gateway_ip=self.scanner.gateway_ip,
            local_ip=self.scanner.local_ip,
        )

        # Initialize WiFi Blocker
        if os.geteuid() == 0:
            try:
                self._wifi_blocker = WiFiBlocker(
                    interface=self.scanner.interface,
                    gateway_ip=self.scanner.gateway_ip,
                )
                self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_red][KILL][/] WiFi Kill Switch armed...")
            except Exception as e:
                self.console.print(f"  [bright_red]✗[/] WiFi Blocker failed: {e}")

        self.console.print()
        self.console.print(f"  [bold bright_green]▸[/] Interface : [bold bright_cyan]{self.scanner.interface}[/]")
        self.console.print(f"  [bold bright_green]▸[/] Gateway   : [bold bright_cyan]{self.scanner.gateway_ip}[/]")
        self.console.print(f"  [bold bright_green]▸[/] Local IP  : [bold bright_cyan]{self.scanner.local_ip}[/]")
        self.console.print(f"  [bold bright_green]▸[/] Subnet    : [bold bright_cyan]{self.scanner.subnet}[/]")
        self.console.print()

    def start(self):
        """Start all modules."""
        signal.signal(signal.SIGINT, self._signal_handler)

        self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_yellow][SCAN][/] Deploying network probes...")
        self.scanner.start_continuous_scan(interval=SCAN_INTERVAL)
        time.sleep(0.5)

        self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_yellow][SPD][/] Speed telemetry online...")
        self.speed_monitor.start(interval=SPEED_INTERVAL)

        self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_yellow][TRF][/] Deep packet inspector armed...")
        self.traffic_analyzer.start()

        # WiFi spy with ARP spoofing
        if os.geteuid() == 0:
            self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_red][ARP][/] ARP poisoning engaged...")
            try:
                self.spy.start()
                self._spy_active = True
                self.console.print(f"  [bold bright_green]▸[/] ARP Spoofing [bold bright_green on grey7] ACTIVE [/]")
            except Exception as e:
                self.console.print(f"  [bright_red]✗[/] ARP failed: {e}")
                self.spy._running = True
                threading.Thread(target=self.spy._sniff_packets, daemon=True).start()
                self._spy_active = True
        else:
            self.console.print(f"  [dim bright_yellow]  ⚠ Requires root for ARP interception[/]")

        # Start live geo tracker
        self.console.print(f"  [dim green]{glitch_text(4)}[/] [bright_magenta][GEO][/] Geo-location tracker online...")
        self._geo_thread = threading.Thread(target=self._geo_track_loop, daemon=True)
        self._geo_thread.start()

        # Start keyboard listener thread
        self._key_thread = threading.Thread(target=self._key_listener, daemon=True)
        self._key_thread.start()

        time.sleep(0.5)
        self.console.print()
        self.console.print(f"  [bold bright_green]██ ALL SYSTEMS OPERATIONAL ██[/]")
        self.console.print(f"  [dim green]Launching cyber interface in 1s...[/]")
        time.sleep(1)

        if self.mode == "dashboard":
            self._run_dashboard()
        elif self.mode == "spy":
            self._run_spy_mode()
        elif self.mode == "map":
            self._run_map_mode()
        elif self.mode == "scan":
            self._run_scan_mode()
        elif self.mode == "traffic":
            self._run_traffic_mode()

    def _signal_handler(self, sig, frame):
        self._running = False
        self.console.print(f"\n  [bright_red]▸▸ GHOST PROTOCOL DISENGAGING...[/]")
        # Restore WiFi if killed
        if self._wifi_kill_active and self._wifi_blocker:
            self.console.print(f"  [bright_yellow]▸ Restoring WiFi for all devices...[/]")
            try:
                self._wifi_blocker.unblock_all()
                self._wifi_blocker.stop()
            except Exception:
                pass
        if self._spy_active:
            self.spy.stop()
        self.scanner.stop()
        self.speed_monitor.stop()
        self.traffic_analyzer.stop()
        self.console.print(f"  [bright_green]✓ Network restored. Ghost out.[/]")
        sys.exit(0)

    # ═══════════════════════════════════════════════════════════════════
    # ─── WIFI KILL SWITCH ────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════

    def _key_listener(self):
        """Background thread: listen for keyboard input for WiFi Kill."""
        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
        except Exception:
            return  # Can't get terminal settings, skip

        try:
            tty.setcbreak(fd)  # Non-blocking single char input
            while self._running:
                if select.select([sys.stdin], [], [], 0.3)[0]:
                    ch = sys.stdin.read(1).lower()
                    if ch == 'k':
                        self._toggle_wifi_kill()
                    elif ch == 'r':
                        self._wifi_restore()
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    def _toggle_wifi_kill(self):
        """Toggle WiFi Kill — block all devices on the network."""
        if not self._wifi_blocker:
            return

        with self._kill_lock:
            if self._wifi_kill_active:
                # Already active, do nothing (press R to restore)
                return

            # Get all devices from scanner
            devices = self.scanner.get_devices()
            gateway_ip = self.scanner.gateway_ip
            my_ip = self.scanner.local_ip
            keep_ips = [gateway_ip, my_ip]

            device_list = []
            for dev in devices:
                if dev.ip not in keep_ips:
                    name = getattr(dev, 'display_name', '') or dev.hostname or ''
                    device_list.append((dev.ip, dev.mac, name))

            if not device_list:
                return

            count = self._wifi_blocker.block_all_except(keep_ips, device_list, duration=0)
            self._wifi_kill_active = True
            self._wifi_kill_count = count

    def _wifi_restore(self):
        """Restore WiFi — unblock all devices."""
        if not self._wifi_blocker:
            return

        with self._kill_lock:
            if not self._wifi_kill_active:
                return
            self._wifi_blocker.unblock_all()
            self._wifi_kill_active = False
            self._wifi_kill_count = 0

    # ═══════════════════════════════════════════════════════════════════
    # ─── LIVE GEO TRACKER ─────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════

    def _geo_track_loop(self):
        """Background thread: resolve destination IPs to locations."""
        while self._running:
            try:
                dst_ips = self.spy.get_destination_ips()
                domain_map = self.spy.get_domain_ip_map()

                traffic_log = self.traffic_analyzer.get_traffic_log(limit=200)
                for entry in traffic_log:
                    dst = entry.get("dst", "")
                    if dst and dst not in ("DNS", ""):
                        if dst not in dst_ips:
                            dst_ips[dst] = {"bytes": 0, "packets": 0, "devices": [], "last_seen": ""}

                for ip in list(dst_ips.keys())[:20]:
                    if not self._running:
                        break
                    geo = self.geo_mapper.lookup(ip)
                    if geo:
                        with self._geo_lock:
                            self._geo_locations[ip] = {
                                "geo": geo,
                                "meta": dst_ips.get(ip, {}),
                                "domain": None,
                            }
                            for domain, d_ip in domain_map.items():
                                if d_ip == ip:
                                    self._geo_locations[ip]["domain"] = domain
                                    break

            except Exception:
                pass
            time.sleep(5)

    # ═══════════════════════════════════════════════════════════════════
    # ─── FULL DASHBOARD ───────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════

    def _run_dashboard(self):
        with Live(self._gen_dashboard(), console=self.console, refresh_per_second=2, screen=True) as live:
            while self._running:
                try:
                    self._frame += 1
                    live.update(self._gen_dashboard())
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    self._running = False
                    break
                except Exception:
                    time.sleep(1)

    def _gen_dashboard(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self._render_header())
        layout["footer"].update(self._render_footer())

        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="center", ratio=3),
            Layout(name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(name="devices", ratio=3),
            Layout(name="speed", ratio=1),
        )

        layout["center"].split_column(
            Layout(name="live_feed", ratio=3),
            Layout(name="searches", ratio=1),
        )

        layout["right"].split_column(
            Layout(name="top_sites", ratio=1),
            Layout(name="map", ratio=1),
            Layout(name="wifi_kill", ratio=1),
        )

        layout["devices"].update(self._render_devices())
        layout["speed"].update(self._render_speed())
        layout["live_feed"].update(self._render_browsing_feed())
        layout["searches"].update(self._render_searches())
        layout["top_sites"].update(self._render_top_sites())
        layout["map"].update(self._render_live_map())
        layout["wifi_kill"].update(self._render_wifi_kill())

        return layout

    # ─── HEADER ───────────────────────────────────────────────────────

    def _render_header(self):
        uptime = str(datetime.now() - self._start_time).split(".")[0]
        now = datetime.now().strftime("%H:%M:%S")
        dev_count = self.scanner.get_online_count()
        total_devs = len(self.scanner.devices)
        spy_stats = self.spy.get_stats()
        scan_time = self.scanner.get_scan_time()

        # Animated scan indicator
        anim = SCAN_ANIM[self._frame % len(SCAN_ANIM)]

        h = Text()
        h.append(f" {anim} ", style="bold bright_green")
        h.append("NEXXUS", style="bold bright_red")
        h.append(" ░▒▓", style="dim green")
        h.append(f" {now} ", style="bright_green")
        h.append(f"UP:{uptime} ", style="dim green")
        h.append(f"◉ {dev_count}/{total_devs} ", style="bold bright_cyan")

        # Scan speed indicator
        if scan_time > 0:
            h.append(f"⚡{scan_time:.1f}s ", style="bright_yellow" if scan_time < 3 else "bright_red")

        if self._spy_active:
            h.append("│", style="dim green")
            h.append(f" DNS:{spy_stats['dns']}", style="bright_cyan")
            h.append(f" TLS:{spy_stats['https']}", style="bright_green")
            h.append(f" HTTP:{spy_stats['http']}", style="bright_yellow")
            h.append(f" 🔎{spy_stats['searches']}", style="bright_magenta")
            h.append(f" PKT:{spy_stats['packets']}", style="dim green")

            with self._geo_lock:
                geo_count = len(self._geo_locations)
            h.append(f" GEO:{geo_count}", style="bright_red")

        # WiFi Kill status — flashing skull when active
        if self._wifi_kill_active:
            h.append(" │", style="dim green")
            skull = "☠" if self._frame % 2 == 0 else "💀"
            h.append(f" {skull} WIFI KILLED ({self._wifi_kill_count}) ", style="bold bright_red blink")

        border = "bright_red" if self._wifi_kill_active else "bright_green"
        return Panel(h, style=border, box=HEAVY, border_style=border)

    # ─── DEVICES ──────────────────────────────────────────────────────

    def _render_devices(self):
        table = Table(
            box=SIMPLE, border_style="green",
            header_style="bold bright_green",
            expand=True, padding=(0, 0),
            show_edge=False,
        )
        table.add_column("#", width=2, justify="center", style="dim green")
        table.add_column("IP", width=13, style="bright_green")
        table.add_column("DEVICE NAME", width=14, overflow="ellipsis", style="bold bright_cyan")
        table.add_column("VENDOR", width=10, overflow="ellipsis", style="dim bright_yellow")
        table.add_column("↓↑", width=9, justify="right", style="bright_green")
        table.add_column("●", width=2, justify="center")

        devices = self.scanner.get_devices()
        devices.sort(key=lambda d: (not d.is_online, d.ip))

        for idx, dev in enumerate(devices[:16], 1):
            if dev.ip == self.scanner.local_ip:
                continue

            spd = self.speed_monitor.get_device_speed(dev.ip)
            spd_str = SpeedMonitor.format_speed(spd["speed_in"])
            
            # ★ Device name — use display_name property
            device_name = dev.display_name
            if device_name == "Unknown" or device_name == "Scanning...":
                # Show resolving animation
                resolve_anim = SCAN_ANIM[self._frame % len(SCAN_ANIM)]
                device_name = f"{resolve_anim} scanning"
            
            # Shorten long names
            device_name = (device_name or "?")[:14]

            # Vendor info
            vendor = dev.vendor if dev.vendor != "Unknown Vendor" else "?"
            vendor = vendor[:10]

            # Status indicator with glow effect
            if dev.is_online:
                pulse = "◉" if self._frame % 2 == 0 else "●"
                status = Text(pulse, style="bold bright_green")
            else:
                status = Text("○", style="dim red")

            # Highlight active devices
            sites = self.spy.get_device_sites(dev.ip)
            site_count = sum(c for _, c in sites)
            row_style = "" 
            if site_count > 5:
                row_style = "on grey7"

            table.add_row(
                str(idx), dev.ip, device_name, vendor,
                spd_str, status, style=row_style
            )

        if not devices:
            anim = SCAN_ANIM[self._frame % len(SCAN_ANIM)]
            table.add_row(
                "-", f"[dim green]{anim} Scanning...[/]", "-", "-", "-",
                Text(anim, style="bright_green")
            )

        return Panel(
            table,
            title="[bold bright_green]◉ TARGETS[/]",
            title_align="left",
            border_style="green",
            box=ROUNDED,
            subtitle=f"[dim green]scan #{self.scanner._scan_count}[/]",
            subtitle_align="right",
        )

    # ─── SPEED ────────────────────────────────────────────────────────

    def _render_speed(self):
        gs = self.speed_monitor.get_global_speed()
        spark_d = self.speed_monitor.get_speed_sparkline(gs["history_down"], width=20)
        spark_u = self.speed_monitor.get_speed_sparkline(gs["history_up"], width=20)

        c = Text()
        c.append(" ▼ ", style="bold bright_green")
        c.append(f"{SpeedMonitor.format_speed(gs['speed_down']):>9} ", style="bold bright_green")
        c.append(f"{spark_d}\n", style="green")
        c.append(" ▲ ", style="bold bright_red")
        c.append(f"{SpeedMonitor.format_speed(gs['speed_up']):>9} ", style="bold bright_red")
        c.append(f"{spark_u}\n", style="bright_red")
        c.append(f" RX:{SpeedMonitor.format_bytes(gs['total_recv'])} TX:{SpeedMonitor.format_bytes(gs['total_sent'])}", style="dim green")

        return Panel(
            c,
            title="[bold bright_green]⚡ BANDWIDTH[/]",
            title_align="left",
            border_style="green",
            box=ROUNDED,
        )

    # ─── BROWSING FEED (with clickable links!) ────────────────────────

    def _render_browsing_feed(self):
        """Live browsing activity — hacker terminal style with clickable links."""
        table = Table(
            box=None, header_style="bold bright_green",
            expand=True, padding=(0, 1), show_edge=False,
        )
        table.add_column("TIME", width=8, style="dim green")
        table.add_column("TARGET", width=13, style="bright_green")
        table.add_column("⚡", width=5, justify="center")
        table.add_column("INTERCEPTED TRAFFIC (click to visit)", style="bright_cyan", overflow="ellipsis", ratio=2)
        table.add_column("CLASS", width=12, style="dim bright_yellow", overflow="ellipsis")

        activity = self.spy.get_global_activity(limit=25)

        if activity:
            for entry in reversed(activity):
                etype = entry["type"]

                # Type badge — hacker style
                type_badges = {
                    "DNS": Text("DNS", style="bright_cyan"),
                    "HTTPS": Text("TLS", style="bold bright_green"),
                    "HTTP": Text("HTTP", style="bold bright_yellow"),
                    "SEARCH": Text("SRCH", style="bold bright_magenta"),
                }
                type_text = type_badges.get(etype, Text(etype[:5], style="dim"))

                # Build clickable link
                clickable_url = entry.get("clickable_url")
                display_text = Text()

                if entry.get("search_query"):
                    display_text.append('» "', style="bright_magenta")
                    display_text.append(entry["search_query"][:40], style="bold bright_magenta")
                    display_text.append('"', style="bright_magenta")
                elif clickable_url:
                    link_display = clickable_url[:50] if len(clickable_url) > 50 else clickable_url
                    display_text.append(
                        f"→ {link_display}",
                        style=f"link {clickable_url} underline bright_cyan"
                    )
                elif entry.get("domain"):
                    url = f"https://{entry['domain']}/"
                    display_text.append(
                        f"→ {entry['domain']}",
                        style=f"link {url} underline bright_cyan"
                    )
                else:
                    display_text.append("?", style="dim")

                # Referer
                if entry.get("referer"):
                    ref_domain = entry["referer"].split("/")[2] if "/" in entry["referer"] else entry["referer"]
                    display_text.append(f" ← {ref_domain[:15]}", style="dim italic green")

                dev = entry["device_ip"]

                # Category
                category = entry.get("category", "")
                cat_styles = {
                    "Social Media": "bright_blue",
                    "Video/Streaming": "bright_red",
                    "Shopping": "bright_green",
                    "Adult": "bold red",
                    "Gaming": "bright_magenta",
                    "Messaging": "bright_yellow",
                    "Search Engine": "bright_cyan",
                }
                cat_style = cat_styles.get(category, "dim green")

                table.add_row(
                    entry["time"], dev, type_text, display_text,
                    Text(category, style=cat_style) if category and category != "Other" else Text("░", style="dim green"),
                )
        else:
            # Fallback
            traffic = self.traffic_analyzer.get_traffic_log(limit=15)
            if traffic:
                for entry in reversed(traffic):
                    proto = entry["proto"]
                    ptype = Text("DNS", style="bright_cyan") if proto == "DNS" else Text("TLS" if proto == "HTTPS" else proto, style="bright_green")
                    domain = entry.get("domain") or entry.get("info", "")
                    link_text = Text()
                    if domain and domain not in ("DNS", ""):
                        url = f"https://{domain}/" if proto == "HTTPS" else f"http://{domain}/"
                        link_text.append(f"→ {domain}", style=f"link {url} underline bright_cyan")
                    else:
                        link_text.append(domain or "?", style="bright_cyan")
                    table.add_row(entry["time"], entry["src"], ptype, link_text, Text("░", style="dim green"))
            else:
                anim = SCAN_ANIM[self._frame % len(SCAN_ANIM)]
                table.add_row(
                    "--:--:--", "--", Text("...", style="dim green"),
                    Text(f"{anim} Intercepting traffic... Links will be clickable", style="dim green"),
                    Text("")
                )

        return Panel(
            table,
            title="[bold bright_red]◉ LIVE INTERCEPT[/] [dim]— click links to visit[/]",
            title_align="left",
            border_style="bright_red",
            box=ROUNDED,
        )

    # ─── SEARCHES ─────────────────────────────────────────────────────

    def _render_searches(self):
        content = Text()
        all_devices = self.spy.get_monitored_devices()
        all_searches = []
        for dev_ip in all_devices:
            queries = self.spy.get_device_searches(dev_ip, limit=10)
            for q in queries:
                all_searches.append((dev_ip, q))

        if all_searches:
            for dev_ip, query in all_searches[-6:]:
                dev_short = ".".join(dev_ip.split(".")[-2:])
                content.append(f" ▸ ", style="bright_magenta")
                content.append(f"[{dev_short}] ", style="dim green")
                content.append(f'"{query}"\n', style="bold bright_magenta")
        else:
            content.append("\n  ░░░ Intercepting search queries...\n", style="dim green")
            content.append("  ░░░ Google • YouTube • Bing\n", style="dim green")

        return Panel(
            content,
            title="[bold bright_magenta]⚡ CAPTURED SEARCHES[/]",
            title_align="left",
            border_style="bright_magenta",
            box=ROUNDED,
        )

    # ─── TOP SITES (with clickable links) ─────────────────────────────

    def _render_top_sites(self):
        table = Table(
            box=None, expand=True, padding=(0, 0),
            show_header=True, header_style="bold bright_green",
        )
        table.add_column("TARGET", width=10, style="dim green")
        table.add_column("DOMAIN", style="bright_cyan", overflow="ellipsis")
        table.add_column("HIT", width=7, justify="right", style="bright_green")
        table.add_column("CLASS", width=10, overflow="ellipsis")

        all_sites = self.spy.get_all_visited_sites(limit=12)

        if all_sites:
            for site in all_sites:
                dev = ".".join(site["device_ip"].split(".")[-2:])
                hits = str(site["count"])
                bar = "█" * min(site["count"], 4)

                domain = site["domain"]
                url = f"https://{domain}/"
                link = Text()
                link.append(f"→ {domain[:18]}", style=f"link {url} underline bright_cyan")

                cat = site["category"]
                cat_styles = {"Social Media": "bright_blue", "Video/Streaming": "bright_red", "Adult": "bold red"}
                cat_style = cat_styles.get(cat, "dim green")

                table.add_row(dev, link, f"{bar}{hits}", Text(cat, style=cat_style))
        else:
            top = self.traffic_analyzer.get_top_domains(limit=8)
            if top:
                for domain, count in top:
                    bar = "█" * min(count, 4)
                    url = f"https://{domain}/"
                    link = Text()
                    link.append(f"→ {domain[:18]}", style=f"link {url} underline bright_cyan")
                    table.add_row("all", link, f"{bar}{count}", Text("░", style="dim green"))
            else:
                table.add_row("-", Text("[dim green]Collecting...[/]"), "-", "-")

        return Panel(
            table,
            title="[bold bright_cyan]◉ TOP TARGETS[/]",
            title_align="left",
            border_style="bright_cyan",
            box=ROUNDED,
        )

    # ─── LIVE GEO MAP ────────────────────────────────────────────────

    def _render_live_map(self):
        """Render live geo tracker — hacker style."""
        with self._geo_lock:
            locations = dict(self._geo_locations)

        if locations:
            geo_map = {ip: info["geo"] for ip, info in locations.items() if info.get("geo")}
            map_lines, labels = self.geo_mapper.render_ascii_map(geo_map, width=35, height=12)

            content = Text()
            # Animated marker
            blink = "◉" if self._frame % 2 == 0 else "●"

            for line in map_lines:
                line = line.replace("●", blink)
                content.append(line + "\n", style="green")

            content.append("\n")
            for ip, info in list(locations.items())[:5]:
                geo = info.get("geo")
                if not geo:
                    continue

                domain = info.get("domain") or ip
                meta = info.get("meta", {})
                pkt_count = meta.get("packets", 0) if isinstance(meta, dict) else 0

                content.append(f" {blink} ", style="bright_red")

                if domain != ip:
                    url = f"https://{domain}/"
                    content.append(f"{domain[:16]}", style=f"link {url} underline bright_magenta")
                else:
                    content.append(f"{ip}", style="bright_magenta")

                content.append(f" {geo.city},{geo.country_code}", style="dim green")

                if pkt_count > 0:
                    content.append(f" [{pkt_count}pkt]", style="dim green")
                content.append("\n")
        else:
            content = Text()
            anim = SCAN_ANIM[self._frame % len(SCAN_ANIM)]
            content.append(f"\n  {anim} GEO-LOCATION TRACKER\n\n", style="bold bright_green")
            content.append("  Resolving traffic destinations...\n", style="dim green")
            content.append("  Locations plotted on world map\n", style="dim green")
            content.append("  as targets browse the web.\n\n", style="dim green")
            content.append("  [DNS+TLS → IP → GEO → MAP]\n", style="dim bright_green")

        return Panel(
            content,
            title="[bold bright_red]◉ GEO TRACKER[/]",
            title_align="left",
            border_style="bright_red",
            box=ROUNDED,
        )

    # ─── FOOTER ───────────────────────────────────────────────────────

    def _render_wifi_kill(self):
        """Render WiFi Kill Switch panel."""
        content = Text()

        if self._wifi_kill_active:
            # Active — show skull animation and blocked count
            skull_art = [
                "    ╔═══════════════════════╗",
                "    ║   ☠  WIFI  KILLED  ☠   ║",
                "    ╚═══════════════════════╝",
            ]
            for line in skull_art:
                content.append(f"{line}\n", style="bold bright_red")

            pulse = "████" if self._frame % 2 == 0 else "▓▓▓▓"
            content.append(f"\n  {pulse} ", style="bold bright_red")
            content.append(f"{self._wifi_kill_count} devices blocked", style="bold bright_red")
            content.append(f" {pulse}\n", style="bold bright_red")

            # Show blocked device IPs
            if self._wifi_blocker:
                blocked = self._wifi_blocker.get_blocked_devices()
                if isinstance(blocked, list):
                    for b in blocked[:6]:
                        ip = b.get('ip', '?') if isinstance(b, dict) else str(b)
                        content.append(f"  ⛔ {ip}\n", style="bright_red")
                    if len(blocked) > 6:
                        content.append(f"  ... +{len(blocked)-6} more\n", style="dim red")

            content.append(f"\n  Press [R] to RESTORE\n", style="bold bright_green")
        else:
            # Inactive — show ready state
            content.append("\n  WiFi Kill Switch\n", style="bold bright_green")
            content.append("  ─────────────────\n", style="dim green")
            content.append(f"\n  Status: ", style="dim green")
            content.append("READY\n", style="bold bright_green")
            content.append(f"  Blocker: ", style="dim green")
            if self._wifi_blocker:
                content.append("ARMED\n", style="bold bright_yellow")
            else:
                content.append("N/A (need root)\n", style="dim red")

            dev_count = len(self.scanner.devices) - 1  # Exclude self
            content.append(f"  Targets: ", style="dim green")
            content.append(f"{max(0, dev_count)} devices\n", style="bright_cyan")

            content.append(f"\n  Press [K] to KILL WiFi\n", style="bold bright_red")
            content.append("  (blocks all devices)\n", style="dim red")

        border = "bright_red" if self._wifi_kill_active else "green"
        title_style = "bold bright_red" if self._wifi_kill_active else "bold bright_yellow"
        skull = "☠" if self._wifi_kill_active else "⚡"
        return Panel(
            content,
            title=f"[{title_style}]{skull} WIFI KILL[/]",
            title_align="left",
            border_style=border,
            box=ROUNDED,
        )

    def _render_footer(self):
        f = Text()
        cyber_glitch = glitch_text(3)

        f.append(f" {cyber_glitch} ", style="dim green")
        f.append("[CTRL+C]", style="bold bright_red")
        f.append(" EXIT ", style="dim bright_green")
        f.append("│", style="dim green")

        if self._spy_active:
            f.append(" ARP:", style="dim green")
            pulse = "██" if self._frame % 2 == 0 else "▓▓"
            f.append(f"{pulse} ", style="bold bright_green")
            f.append("FWD:", style="dim green")
            f.append(f"{pulse} ", style="bold bright_green")
        else:
            f.append(" ARP:", style="dim green")
            f.append("OFF ", style="bright_red")

        f.append("│", style="dim green")

        # WiFi Kill keybinds
        if self._wifi_kill_active:
            kill_pulse = "☠" if self._frame % 2 == 0 else "💀"
            f.append(f" {kill_pulse} ", style="bold bright_red")
            f.append("[R]", style="bold bright_green")
            f.append("RESTORE ", style="dim bright_green")
        else:
            f.append(" [K]", style="bold bright_red")
            f.append("KILL ", style="dim bright_red")

        f.append("│", style="dim green")
        f.append(" → Click links to open ", style="bold bright_cyan")
        f.append(f" {cyber_glitch}", style="dim green")

        border = "bright_red" if self._wifi_kill_active else "green"
        return Panel(f, style=border, box=HEAVY, border_style=border)

    # ═══════════════════════════════════════════════════════════════════
    # ─── SINGLE MODES ─────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════

    def _run_spy_mode(self):
        """Focused WiFi spy view."""
        def render():
            self._frame += 1
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3),
            )
            layout["header"].update(self._render_header())
            layout["footer"].update(self._render_footer())
            layout["body"].split_row(
                Layout(name="feed", ratio=3),
                Layout(name="side", ratio=2),
            )
            layout["feed"].update(self._render_browsing_feed())
            layout["side"].split_column(
                Layout(name="sites", ratio=2),
                Layout(name="searches", ratio=1),
            )
            layout["sites"].update(self._render_top_sites())
            layout["searches"].update(self._render_searches())
            return layout

        with Live(render(), console=self.console, refresh_per_second=2, screen=True) as live:
            while self._running:
                try:
                    live.update(render())
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    break

    def _run_map_mode(self):
        """Live geo tracker full screen."""
        def render():
            self._frame += 1
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3),
            )
            layout["header"].update(self._render_header())
            layout["footer"].update(self._render_footer())
            layout["body"].split_row(
                Layout(name="map", ratio=3),
                Layout(name="feed", ratio=2),
            )
            layout["map"].update(self._render_live_map())
            layout["feed"].update(self._render_browsing_feed())
            return layout

        with Live(render(), console=self.console, refresh_per_second=2, screen=True) as live:
            while self._running:
                try:
                    live.update(render())
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    break

    def _run_scan_mode(self):
        def render():
            self._frame += 1
            return self._render_devices()

        with Live(render(), console=self.console, refresh_per_second=2) as live:
            while self._running:
                try:
                    live.update(render())
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    break

    def _run_traffic_mode(self):
        def render():
            self._frame += 1
            return self._render_browsing_feed()

        with Live(render(), console=self.console, refresh_per_second=2) as live:
            while self._running:
                try:
                    live.update(render())
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    break


ATTACK_MENU = """

  [bold bright_cyan]╔═════════════════════════════════════════════════════════╗[/]
  [bold bright_cyan]║[/]  [bold bright_green]☠  NEXXUS ATTACK MODULES[/]                           [bold bright_cyan]║[/]
  [bold bright_cyan]╠═════════════════════════════════════════════════════════╣[/]
  [bold bright_cyan]║[/]                                                         [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][1][/] [bright_green]📶 Full Dashboard[/]     — Complete recon interface  [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][2][/] [bright_green]🔍 WiFi Spy[/]            — Intercept browsing data   [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][3][/] [bright_green]☠  WiFi Kill[/]           — Block ALL devices         [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][4][/] [bright_green]🌍 Geo Tracker[/]         — Live location mapping     [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][5][/] [bright_green]📡 Network Scan[/]        — Discover all devices      [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][6][/] [bright_green]📦 Traffic Monitor[/]     — Deep packet inspection    [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][7][/] [bright_green]🔐 Device Spy[/]          — Full intelligence suite   [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]                                                         [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]  [bold bright_red][0][/] [dim]Exit[/]                                           [bold bright_cyan]║[/]
  [bold bright_cyan]║[/]                                                         [bold bright_cyan]║[/]
  [bold bright_cyan]╚═════════════════════════════════════════════════════════╝[/]
"""


def _print_banner(console):
    """Print the NEXXUS TOOLS banner with skull art."""
    console.print(f"[bright_red]{SKULL_ART}[/]")
    console.print(f"[bold bright_cyan]{NEXXUS_BANNER}[/]")
    console.print(f"[dim bright_cyan]{'=' * 58}[/]")
    console.print(f"[bold bright_green]  \u2620  NEXXUS TOOLS v{VERSION} \u2014 WiFi Cyber Arsenal  \u2620[/]")
    console.print(f"[dim green]  Author: [bold bright_cyan]{AUTHOR}[/][dim green]  |  github.com/{AUTHOR}/nexxus-tools[/]")
    console.print(f"[dim green]  \u26a0  For authorized penetration testing only![/]")
    console.print(f"[dim bright_cyan]{'=' * 58}[/]")


def main():
    parser = argparse.ArgumentParser(
        description=f"NEXXUS TOOLS v{VERSION} \u2014 WiFi Cyber Arsenal by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
\u2620  NEXXUS TOOLS v{VERSION} \u2014 by {AUTHOR}
\u26a0  For authorized penetration testing and educational use ONLY!

Attack Modes:
  sudo python3 netvision.py              Interactive attack menu
  sudo python3 netvision.py --dashboard  Full hacker dashboard
  sudo python3 netvision.py --spy        WiFi spy (intercept traffic)
  sudo python3 netvision.py --kill       WiFi Kill (block all devices)
  sudo python3 netvision.py --map        Live geo tracker
  sudo python3 netvision.py --scan       Device scan
  sudo python3 netvision.py --traffic    Traffic feed
  sudo python3 netvision.py --deauth     WiFi deauth jammer
  sudo python3 netvision.py --portal     Captive portal phishing
  sudo python3 netvision.py -i wlan0     Specify interface

Modules:
  \ud83d\udce1 Network Scanner     \u2014 Multi-layer device discovery (ARP+nmap)
  \ud83d\udd0d WiFi Spy            \u2014 ARP spoof + packet interception
  \u2620  WiFi Kill           \u2014 ARP poison to disconnect all devices
  \ud83c\udf10 DNS Spoofer         \u2014 Redirect DNS queries
  \ud83d\udd12 MITM Proxy          \u2014 SSL strip + traffic injection
  \ud83c\udfa3 Captive Portal      \u2014 Phishing login pages
  \ud83d\udce1 Deauth Jammer       \u2014 WiFi deauthentication attack
  \ud83c\udf0d Geo Tracker         \u2014 Map traffic destinations
  \ud83d\udd11 Credential Sniffer  \u2014 Capture login forms
  \ud83d\udcc1 Download Tracker    \u2014 Intercept file downloads
        """
    )

    parser.add_argument("-i", "--interface", help="WiFi interface", default=None)
    parser.add_argument("--dashboard", action="store_true", help="Full dashboard mode")
    parser.add_argument("--scan", action="store_true", help="Device scan only")
    parser.add_argument("--traffic", action="store_true", help="Traffic feed only")
    parser.add_argument("--map", action="store_true", help="Live geo tracker")
    parser.add_argument("--spy", action="store_true", help="WiFi spy mode")
    parser.add_argument("--kill", action="store_true", help="WiFi Kill mode")
    parser.add_argument("--deauth", action="store_true", help="Deauth jammer mode")
    parser.add_argument("--portal", action="store_true", help="Captive portal mode")

    args = parser.parse_args()

    console = Console(highlight=False)

    # Root check
    if os.geteuid() != 0:
        _print_banner(console)
        console.print()
        console.print(Panel(
            "[bold bright_red]\u26a0 ROOT ACCESS REQUIRED[/]\n\n"
            "Execute: [bold bright_green]sudo python3 netvision.py[/]\n\n"
            "[dim green]NEXXUS TOOLS needs root for ARP spoofing,\n"
            "packet capture, and network attacks.[/]",
            border_style="bright_red", box=DOUBLE,
            title=f"[bold bright_red]\u2620 ACCESS DENIED[/]",
        ))
        sys.exit(1)

    # Direct mode from CLI args
    mode = None
    if args.dashboard: mode = "dashboard"
    elif args.scan: mode = "scan"
    elif args.traffic: mode = "traffic"
    elif args.map: mode = "map"
    elif args.spy: mode = "spy"
    elif args.kill: mode = "dashboard"  # Dashboard with auto-kill

    # Interactive attack menu if no mode specified
    if mode is None:
        _print_banner(console)
        console.print(ATTACK_MENU)

        while True:
            console.print(f"  [bold bright_red]\u2620[/] [bold bright_cyan]nexxus[/] [bold bright_green]>[/] ", end="")
            try:
                choice = input().strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [bright_red]\u25b8 Exiting NEXXUS TOOLS...[/]")
                sys.exit(0)

            if choice == "1":
                mode = "dashboard"
                break
            elif choice == "2":
                mode = "spy"
                break
            elif choice == "3":
                mode = "dashboard"  # Dashboard + auto WiFi kill
                args.kill = True
                break
            elif choice == "4":
                mode = "map"
                break
            elif choice == "5":
                mode = "scan"
                break
            elif choice == "6":
                mode = "traffic"
                break
            elif choice == "7":
                console.print("  [bright_green]\u25b8 Launching Device Spy...[/]")
                console.print("  [dim]Run: sudo python3 device_spy.py --all[/]")
                os.system("sudo python3 device_spy.py --all")
                sys.exit(0)
            elif choice == "0" or choice.lower() in ("q", "quit", "exit"):
                console.print("  [bright_red]\u25b8 Exiting NEXXUS TOOLS...[/]")
                sys.exit(0)
            else:
                console.print("  [bright_red]Invalid option. Choose 0-7.[/]")

    console.print()
    console.print(f"  [bold bright_green]\u25b8 Loading attack module...[/]")
    time.sleep(0.3)

    dashboard = NetVisionDashboard(interface=args.interface, mode=mode)

    # Auto-trigger WiFi Kill if --kill flag
    if args.kill:
        console.print(f"  [bold bright_red]\u2620 AUTO-KILL: WiFi Kill will activate after scan...[/]")
        def auto_kill():
            time.sleep(8)  # Wait for scan to complete
            dashboard._toggle_wifi_kill()
        threading.Thread(target=auto_kill, daemon=True).start()

    dashboard.start()


if __name__ == "__main__":
    main()
