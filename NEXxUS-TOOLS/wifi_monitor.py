#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🕵️  NetVision WiFi Activity Monitor                            ║
║   See what websites people on your WiFi are visiting             ║
║                                                                  ║
║   Usage: sudo python3 wifi_monitor.py                            ║
║   Usage: sudo python3 wifi_monitor.py -i wlan0                   ║
║   Usage: sudo python3 wifi_monitor.py --target 192.168.1.105     ║
╚══════════════════════════════════════════════════════════════════╝

"""

import sys
import os
import signal
import argparse
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
    from rich.box import HEAVY, ROUNDED, DOUBLE, SIMPLE, MINIMAL, SQUARE
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("Error: 'rich' library required. Install: pip install rich")
    sys.exit(1)

from scanner import NetworkScanner
from wifi_spy import WiFiActivityMonitor
from speed_monitor import SpeedMonitor
from geo_mapper import GeoMapper


class WiFiMonitorDashboard:
    """
    Terminal dashboard that shows what websites/URLs people 
    on your WiFi network are visiting in real-time.
    """

    BANNER = """[bold bright_cyan]
 ██╗    ██╗██╗███████╗██╗    ███████╗██████╗ ██╗   ██╗
 ██║    ██║██║██╔════╝██║    ██╔════╝██╔══██╗╚██╗ ██╔╝
 ██║ █╗ ██║██║█████╗  ██║    ███████╗██████╔╝ ╚████╔╝ 
 ██║███╗██║██║██╔══╝  ██║    ╚════██║██╔═══╝   ╚██╔╝  
 ╚███╔███╔╝██║██║     ██║    ███████║██║        ██║   
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚═╝        ╚═╝   
[/][bold bright_white]
     WiFi Activity Monitor — See What They're Browsing
[/]"""

    def __init__(self, interface=None, targets=None):
        self.console = Console()
        self._running = True
        self._start_time = datetime.now()
        self._selected_device = None

        # Print banner
        self.console.print(self.BANNER)
        self.console.print()

        # Initialize scanner
        self.console.print(Panel(
            "[bright_cyan]⟐ Initializing WiFi Activity Monitor...[/]",
            border_style="bright_blue", box=ROUNDED
        ))

        self.scanner = NetworkScanner(interface=interface)
        self.speed_monitor = SpeedMonitor(interface=self.scanner.interface)
        self.geo_mapper = GeoMapper()

        self.console.print(f"  [bright_green]✓[/] Interface:  [bold]{self.scanner.interface}[/]")
        self.console.print(f"  [bright_green]✓[/] Gateway:    [bold]{self.scanner.gateway_ip}[/]")
        self.console.print(f"  [bright_green]✓[/] Local IP:   [bold]{self.scanner.local_ip}[/]")
        self.console.print(f"  [bright_green]✓[/] Subnet:     [bold]{self.scanner.subnet}[/]")

        # Initialize WiFi spy
        self.spy = WiFiActivityMonitor(
            interface=self.scanner.interface,
            gateway_ip=self.scanner.gateway_ip,
            local_ip=self.scanner.local_ip,
            targets=targets or [],
        )

        if targets:
            self.console.print(f"  [bright_yellow]⟐[/] Monitoring targets: [bold]{', '.join(targets)}[/]")
        else:
            self.console.print(f"  [bright_yellow]⟐[/] Monitoring: [bold]ALL devices on network[/]")

        self.console.print()

    def start(self):
        """Start monitoring."""
        signal.signal(signal.SIGINT, self._signal_handler)

        # Check root
        if os.geteuid() != 0:
            self.console.print(Panel(
                "[bold bright_red]ERROR:[/] This tool REQUIRES root privileges.\n"
                "ARP spoofing and packet capture need sudo.\n\n"
                "Run: [bold bright_cyan]sudo python3 wifi_monitor.py[/]",
                title="[bold bright_red]⚠ Permission Error[/]",
                border_style="bright_red", box=ROUNDED,
            ))
            sys.exit(1)

        # Start scanner
        self.console.print("[bright_yellow]⟐ Scanning network for devices...[/]")
        self.scanner.start_continuous_scan(interval=10)
        self.speed_monitor.start(interval=3)
        time.sleep(2)

        devices = self.scanner.get_devices()
        self.console.print(f"  [bright_green]✓[/] Found [bold]{len(devices)}[/] device(s)")

        # Start ARP spoofing + sniffing
        self.console.print("[bright_yellow]⟐ Starting ARP interception...[/]")
        try:
            self.spy.start()
            self.console.print("  [bright_green]✓[/] ARP spoofing active — intercepting traffic")
        except Exception as e:
            self.console.print(f"  [bright_red]✗[/] ARP spoof failed: {e}")
            self.console.print("  [bright_yellow]⟐[/] Falling back to passive sniffing...")
            # Start just the sniffer without ARP spoof
            self.spy._running = True
            threading.Thread(target=self.spy._sniff_packets, daemon=True).start()

        self.console.print("[bright_green]⟐ Dashboard starting... Ctrl+C to stop[/]\n")
        time.sleep(1)

        # Run dashboard
        self._run_dashboard()

    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C — restore ARP tables and exit cleanly."""
        self._running = False
        self.console.print("\n[bright_yellow]⟐ Restoring ARP tables...[/]")
        self.spy.stop()
        self.scanner.stop()
        self.speed_monitor.stop()
        self.console.print("[bright_green]✓ Network restored. Exiting.[/]")
        sys.exit(0)

    def _run_dashboard(self):
        """Run the live dashboard."""
        with Live(
            self._render_dashboard(),
            console=self.console,
            refresh_per_second=1,
            screen=True,
        ) as live:
            while self._running:
                try:
                    live.update(self._render_dashboard())
                    time.sleep(1)
                except KeyboardInterrupt:
                    self._running = False
                    break
                except Exception:
                    time.sleep(1)

    def _render_dashboard(self):
        """Generate the full dashboard layout."""
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
            Layout(name="right", ratio=3),
        )

        layout["left"].split_column(
            Layout(name="devices", ratio=2),
            Layout(name="stats", ratio=1),
        )

        layout["right"].split_column(
            Layout(name="live_feed", ratio=2),
            Layout(name="sites_and_searches", ratio=2),
        )

        layout["devices"].update(self._render_devices())
        layout["stats"].update(self._render_stats())
        layout["live_feed"].update(self._render_live_feed())
        layout["sites_and_searches"].update(self._render_sites_and_searches())

        return layout

    def _render_header(self):
        """Render header bar."""
        now = datetime.now().strftime("%H:%M:%S")
        uptime = str(datetime.now() - self._start_time).split(".")[0]
        stats = self.spy.get_stats()

        header = Text()
        header.append(" 🕵️ WiFi Spy ", style="bold bright_cyan on dark_blue")
        header.append(f"  ⏱ {now}  ", style="bright_white")
        header.append(f"  ⬆ {uptime}  ", style="dim")
        header.append(f"  📡 {stats['devices']} devices  ", style="bright_green")
        header.append(f"  📦 {stats['packets']} pkts  ", style="dim bright_white")
        header.append(f"  🔍 DNS:{stats['dns']}  ", style="bright_cyan")
        header.append(f"  🔒 HTTPS:{stats['https']}  ", style="bright_green")
        header.append(f"  🌐 HTTP:{stats['http']}  ", style="bright_yellow")
        header.append(f"  🔎 Searches:{stats['searches']}  ", style="bright_magenta")

        return Panel(header, style="bright_blue", box=HEAVY)

    def _render_devices(self):
        """Render monitored devices panel."""
        table = Table(
            box=ROUNDED,
            border_style="bright_blue",
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )

        table.add_column("#", width=3, justify="center", style="dim")
        table.add_column("IP Address", width=15, style="bright_white")
        table.add_column("Hostname", width=16, overflow="ellipsis", style="bright_cyan")
        table.add_column("Vendor", width=12, overflow="ellipsis", style="bright_yellow")
        table.add_column("Sites", width=6, justify="right", style="bright_green")
        table.add_column("Status", width=6, justify="center")

        devices = self.scanner.get_devices()
        devices.sort(key=lambda d: (not d.is_online, d.ip))

        for idx, dev in enumerate(devices[:15], 1):
            if dev.ip == self.scanner.local_ip:
                continue  # Skip ourselves

            sites = self.spy.get_device_sites(dev.ip)
            site_count = sum(c for _, c in sites)

            status = Text("● ON", style="bold bright_green") if dev.is_online else Text("○", style="dim red")

            row_style = ""
            if site_count > 0:
                row_style = "on grey11"

            table.add_row(
                str(idx),
                dev.ip,
                (dev.hostname or "Unknown")[:16],
                (dev.vendor or "?")[:12],
                str(site_count) if site_count > 0 else "-",
                status,
                style=row_style,
            )

        if not devices:
            table.add_row("-", "[dim]Scanning...[/]", "-", "-", "-", Text("⟳", style="bright_yellow"))

        return Panel(table, title="📡 Network Devices", title_align="left",
                     border_style="bright_blue", box=ROUNDED)

    def _render_stats(self):
        """Render statistics panel."""
        stats = self.spy.get_stats()

        content = Text()
        content.append("\n")
        content.append("  📦 Packets:   ", style="dim bright_white")
        content.append(f"{stats['packets']:,}\n", style="bold bright_white")
        content.append("  🔍 DNS:       ", style="bright_cyan")
        content.append(f"{stats['dns']:,}\n", style="bold bright_cyan")
        content.append("  🔒 HTTPS:     ", style="bright_green")
        content.append(f"{stats['https']:,}\n", style="bold bright_green")
        content.append("  🌐 HTTP:      ", style="bright_yellow")
        content.append(f"{stats['http']:,}\n", style="bold bright_yellow")
        content.append("  🔎 Searches:  ", style="bright_magenta")
        content.append(f"{stats['searches']:,}\n", style="bold bright_magenta")
        content.append("  ⚡ ARP Sent:  ", style="bright_red")
        content.append(f"{stats['arp_sent']:,}\n", style="bold bright_red")

        # Connection speed
        speed = self.speed_monitor.get_global_speed()
        content.append("\n")
        content.append(f"  ⬇ {SpeedMonitor.format_speed(speed['speed_down']):>10}  ", style="bright_green")
        content.append(f"⬆ {SpeedMonitor.format_speed(speed['speed_up']):>10}\n", style="bright_red")

        return Panel(content, title="📊 Stats", title_align="left",
                     border_style="bright_magenta", box=ROUNDED)

    def _render_live_feed(self):
        """Render the live browsing activity feed."""
        table = Table(
            box=SIMPLE,
            header_style="bold bright_white",
            expand=True,
            padding=(0, 1),
            show_edge=False,
        )

        table.add_column("Time", width=8, style="dim")
        table.add_column("Device", width=12, style="bright_white")
        table.add_column("Type", width=6, justify="center")
        table.add_column("Website / URL", style="bright_cyan", overflow="ellipsis")
        table.add_column("Category", width=12, style="dim bright_yellow", overflow="ellipsis")

        activity = self.spy.get_global_activity(limit=20)

        for entry in reversed(activity):
            # Color by type
            entry_type = entry["type"]
            if entry_type == "DNS":
                type_text = Text("DNS", style="bright_cyan")
            elif entry_type == "HTTPS":
                type_text = Text("HTTPS", style="bright_green")
            elif entry_type == "HTTP":
                type_text = Text("HTTP", style="bright_yellow")
            elif entry_type == "SEARCH":
                type_text = Text("🔎", style="bold bright_magenta")
            else:
                type_text = Text(entry_type, style="dim")

            # Display domain or URL
            display = entry.get("url") or entry.get("domain") or "?"

            # Search query highlight
            if entry.get("search_query"):
                display = f'🔎 "{entry["search_query"]}"'

            # Shorten IP
            device = entry["device_ip"]
            device_short = ".".join(device.split(".")[-2:])

            # Get category from the activity entry in the global log
            category = ""
            domain = entry.get("domain", "")
            if domain:
                category = self.spy._categorize_domain(domain)

            table.add_row(
                entry["time"],
                device_short,
                type_text,
                display[:45],
                category,
            )

        if not activity:
            table.add_row(
                "--:--:--", "--", Text("...", style="dim"),
                "[dim italic]Waiting for browsing activity...[/]", ""
            )

        return Panel(table, title="🔴 Live Browsing Feed", title_align="left",
                     border_style="bright_red", box=ROUNDED)

    def _render_sites_and_searches(self):
        """Render top visited sites and search queries."""
        # Split into two tables side by side
        # Top sites
        sites_table = Table(
            title="🌐 Top Visited Sites",
            title_style="bold bright_cyan",
            box=MINIMAL,
            expand=True,
            padding=(0, 1),
        )
        sites_table.add_column("Device", width=10, style="dim bright_white")
        sites_table.add_column("Website", style="bright_cyan", overflow="ellipsis")
        sites_table.add_column("Visits", width=6, justify="right", style="bright_green")
        sites_table.add_column("Category", width=12, style="dim bright_yellow")

        all_sites = self.spy.get_all_visited_sites(limit=12)
        for site in all_sites:
            device_short = ".".join(site["device_ip"].split(".")[-2:])
            visits = str(site["count"])

            # Color bar
            bar_len = min(site["count"], 10)
            bar = "█" * bar_len

            sites_table.add_row(
                device_short,
                site["domain"][:28],
                f"{bar} {visits}",
                site["category"],
            )

        if not all_sites:
            sites_table.add_row("--", "[dim]No sites captured yet...[/]", "--", "--")

        # Search queries section
        search_text = Text()
        search_text.append("\n ─── 🔎 Search Queries ───\n", style="bold bright_magenta")

        # Gather all search queries across devices
        all_devices = self.spy.get_monitored_devices()
        all_searches = []
        for dev_ip in all_devices:
            queries = self.spy.get_device_searches(dev_ip, limit=5)
            for q in queries:
                all_searches.append((dev_ip, q))

        for dev_ip, query in all_searches[-8:]:
            dev_short = ".".join(dev_ip.split(".")[-2:])
            search_text.append(f"  [{dev_short}] ", style="dim bright_white")
            search_text.append(f'"{query}"\n', style="bold bright_magenta")

        if not all_searches:
            search_text.append("  [dim]No search queries captured yet...[/]\n")

        content = Group(sites_table, search_text)

        return Panel(content, title="📊 Browsing Analysis", title_align="left",
                     border_style="bright_green", box=ROUNDED)

    def _render_footer(self):
        """Render footer bar."""
        footer = Text()
        footer.append(" [Ctrl+C]", style="bold bright_red")
        footer.append(" Stop & Restore  ", style="bright_white")
        footer.append("│ ", style="dim")
        footer.append("ARP Spoof: ", style="dim bright_white")
        footer.append("ACTIVE ", style="bold bright_green")
        footer.append("│ ", style="dim")
        footer.append("IP Forward: ", style="dim bright_white")
        footer.append("ON ", style="bold bright_green")
        footer.append("│ ", style="dim")
        footer.append(f"🕵️  NetVision WiFi Spy v1.0  ", style="dim bright_white")
        footer.append("⚠ Educational Use Only", style="dim bright_yellow")

        return Panel(footer, style="bright_blue", box=HEAVY)


def main():
    parser = argparse.ArgumentParser(
        description="🕵️ NetVision WiFi Activity Monitor — See what people browse on your WiFi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 wifi_monitor.py                    Monitor all devices
  sudo python3 wifi_monitor.py -i wlan0            Specify WiFi interface
  sudo python3 wifi_monitor.py -t 192.168.1.105    Monitor specific device
  sudo python3 wifi_monitor.py -t 192.168.1.105 -t 192.168.1.110  Multiple targets

⚠️  This tool uses ARP spoofing — only use on your OWN network!
        """
    )

    parser.add_argument(
        "-i", "--interface",
        help="WiFi interface (auto-detected if not specified)",
        default=None,
    )
    parser.add_argument(
        "-t", "--target",
        action="append",
        help="Target device IP(s) to monitor (default: all)",
        default=None,
    )

    args = parser.parse_args()

    # Launch
    dashboard = WiFiMonitorDashboard(
        interface=args.interface,
        targets=args.target,
    )
    dashboard.start()


if __name__ == "__main__":
    main()
