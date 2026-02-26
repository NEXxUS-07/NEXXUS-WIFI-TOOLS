"""
NetVision — Geolocation Module
Maps IP addresses to geographical locations and renders ASCII maps.
"""

import threading
import time
import json
import os
from datetime import datetime
from collections import defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from config import GEO_API_URL, GEO_API_RATE_LIMIT, GEO_CACHE_TTL


class GeoLocation:
    """Represents geographical location data for an IP."""

    def __init__(self, ip, data):
        self.ip = ip
        self.lat = data.get("lat", 0.0)
        self.lon = data.get("lon", 0.0)
        self.city = data.get("city", "Unknown")
        self.region = data.get("regionName", "Unknown")
        self.country = data.get("country", "Unknown")
        self.country_code = data.get("countryCode", "??")
        self.isp = data.get("isp", "Unknown")
        self.org = data.get("org", "Unknown")
        self.timezone = data.get("timezone", "Unknown")
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            "ip": self.ip,
            "lat": self.lat,
            "lon": self.lon,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "country_code": self.country_code,
            "isp": self.isp,
            "org": self.org,
            "timezone": self.timezone,
        }

    def short_str(self):
        """Short location description."""
        return f"{self.city}, {self.country_code}"

    def full_str(self):
        """Full location description."""
        return f"{self.city}, {self.region}, {self.country} ({self.isp})"


class GeoMapper:
    """Maps IPs to locations and renders ASCII geographical maps."""

    def __init__(self):
        self._cache = {}  # IP -> GeoLocation
        self._lock = threading.Lock()
        self._request_count = 0
        self._last_reset = time.time()
        self._cache_file = os.path.join(os.path.dirname(__file__), ".geo_cache.json")
        self._load_cache()

    def _load_cache(self):
        """Load cached geolocation data from disk."""
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, "r") as f:
                    data = json.load(f)
                    for ip, info in data.items():
                        self._cache[ip] = GeoLocation(ip, info)
        except (json.JSONDecodeError, IOError):
            pass

    def _save_cache(self):
        """Save geolocation cache to disk."""
        try:
            data = {}
            with self._lock:
                for ip, geo in self._cache.items():
                    data[ip] = geo.to_dict()

            with open(self._cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except IOError:
            pass

    def _rate_limit_ok(self):
        """Check if we're within rate limits."""
        now = time.time()
        if now - self._last_reset > 60:
            self._request_count = 0
            self._last_reset = now

        return self._request_count < GEO_API_RATE_LIMIT

    def lookup(self, ip):
        """Look up geolocation for an IP address."""
        # Skip private/local IPs
        if self._is_private_ip(ip):
            return None

        # Check cache
        with self._lock:
            if ip in self._cache:
                cached = self._cache[ip]
                age = (datetime.now() - cached.timestamp).seconds
                if age < GEO_CACHE_TTL:
                    return cached

        # Rate limit check
        if not self._rate_limit_ok():
            return self._cache.get(ip)

        # API lookup
        if not REQUESTS_AVAILABLE:
            return None

        try:
            url = GEO_API_URL.format(ip=ip)
            response = requests.get(url, timeout=5)
            self._request_count += 1

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    geo = GeoLocation(ip, data)
                    with self._lock:
                        self._cache[ip] = geo
                    self._save_cache()
                    return geo

        except (requests.RequestException, json.JSONDecodeError, KeyError):
            pass

        return None

    def lookup_batch(self, ips):
        """Look up multiple IPs (respecting rate limits)."""
        results = {}
        for ip in ips:
            geo = self.lookup(ip)
            if geo:
                results[ip] = geo
        return results

    def _is_private_ip(self, ip):
        """Check if an IP address is private/local."""
        parts = ip.split(".")
        if len(parts) != 4:
            return True

        try:
            first = int(parts[0])
            second = int(parts[1])

            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 0:
                return True
            if first >= 224:
                return True

        except ValueError:
            return True

        return False

    def render_ascii_map(self, locations, width=78, height=22, highlight_ip=None):
        """
        Render an ASCII world map with device location markers.

        Args:
            locations: dict of IP -> GeoLocation
            width: Map width in characters
            height: Map height in characters
            highlight_ip: IP to highlight on map

        Returns:
            List of strings (map lines)
        """
        # Simplified ASCII world map outline
        world_map = self._get_world_map_template(width, height)

        # Place markers for each location
        markers = {}
        marker_labels = []
        idx = 1

        for ip, geo in locations.items():
            x, y = self._latlon_to_xy(geo.lat, geo.lon, width, height)

            # Ensure within bounds
            x = max(0, min(x, width - 1))
            y = max(0, min(y, height - 1))

            key = (x, y)
            if key in markers:
                markers[key]["count"] += 1
                markers[key]["ips"].append(ip)
            else:
                marker_char = str(idx) if idx <= 9 else chr(ord('A') + idx - 10)
                markers[key] = {
                    "char": marker_char,
                    "count": 1,
                    "ips": [ip],
                    "geo": geo,
                    "highlight": ip == highlight_ip,
                }
                marker_labels.append({
                    "idx": marker_char,
                    "city": geo.city,
                    "country": geo.country_code,
                    "ips": [ip],
                })
                idx += 1

        # Render map with markers
        map_lines = []
        for y, row in enumerate(world_map):
            line = list(row)
            for (mx, my), marker in markers.items():
                if my == y:
                    char = marker["char"]
                    if marker["highlight"]:
                        char = f"◉"
                    elif marker["count"] > 1:
                        char = "◆"
                    else:
                        char = "●"

                    if 0 <= mx < len(line):
                        line[mx] = char

            map_lines.append("".join(line))

        return map_lines, marker_labels

    def _latlon_to_xy(self, lat, lon, width, height):
        """Convert latitude/longitude to x,y coordinates on ASCII map."""
        # Mercator-like projection
        x = int((lon + 180) / 360 * width)
        y = int((90 - lat) / 180 * height)
        return x, y

    def _get_world_map_template(self, width=78, height=22):
        """Generate a simplified ASCII world map template."""
        # Create empty map
        template = []
        for _ in range(height):
            template.append("·" * width)

        # Draw simplified continent outlines
        # This is a simplified representation using dots and characters
        continents = self._get_continent_coords(width, height)

        map_grid = [list(row) for row in template]

        for cx, cy in continents:
            if 0 <= cy < height and 0 <= cx < width:
                map_grid[cy][cx] = "░"

        return ["".join(row) for row in map_grid]

    def _get_continent_coords(self, width, height):
        """Get simplified continent outline coordinates scaled to map size."""
        coords = []

        # Scale factors
        sx = width / 78.0
        sy = height / 22.0

        # North America
        na_coords = [
            (8,3),(9,3),(10,3),(11,3),(12,3),(13,3),(14,3),(15,3),
            (7,4),(8,4),(9,4),(10,4),(11,4),(12,4),(13,4),(14,4),(15,4),(16,4),
            (8,5),(9,5),(10,5),(11,5),(12,5),(13,5),(14,5),(15,5),(16,5),(17,5),
            (9,6),(10,6),(11,6),(12,6),(13,6),(14,6),(15,6),(16,6),(17,6),(18,6),
            (10,7),(11,7),(12,7),(13,7),(14,7),(15,7),(16,7),(17,7),(18,7),
            (12,8),(13,8),(14,8),(15,8),(16,8),(17,8),(18,8),
            (14,9),(15,9),(16,9),(17,9),
            (15,10),(16,10),(17,10),
        ]

        # South America
        sa_coords = [
            (18,11),(19,11),(20,11),(21,11),
            (17,12),(18,12),(19,12),(20,12),(21,12),(22,12),
            (17,13),(18,13),(19,13),(20,13),(21,13),(22,13),
            (18,14),(19,14),(20,14),(21,14),(22,14),
            (18,15),(19,15),(20,15),(21,15),
            (19,16),(20,16),(21,16),
            (19,17),(20,17),
            (20,18),
        ]

        # Europe
        eu_coords = [
            (35,3),(36,3),(37,3),(38,3),(39,3),(40,3),
            (34,4),(35,4),(36,4),(37,4),(38,4),(39,4),(40,4),(41,4),
            (34,5),(35,5),(36,5),(37,5),(38,5),(39,5),(40,5),(41,5),
            (35,6),(36,6),(37,6),(38,6),(39,6),(40,6),
            (36,7),(37,7),(38,7),(39,7),
        ]

        # Africa
        af_coords = [
            (36,8),(37,8),(38,8),(39,8),(40,8),(41,8),
            (35,9),(36,9),(37,9),(38,9),(39,9),(40,9),(41,9),(42,9),
            (35,10),(36,10),(37,10),(38,10),(39,10),(40,10),(41,10),(42,10),
            (36,11),(37,11),(38,11),(39,11),(40,11),(41,11),(42,11),
            (36,12),(37,12),(38,12),(39,12),(40,12),(41,12),
            (37,13),(38,13),(39,13),(40,13),(41,13),
            (38,14),(39,14),(40,14),
            (38,15),(39,15),
        ]

        # Asia
        as_coords = [
            (42,2),(43,2),(44,2),(45,2),(46,2),(47,2),(48,2),(49,2),(50,2),(51,2),
            (41,3),(42,3),(43,3),(44,3),(45,3),(46,3),(47,3),(48,3),(49,3),(50,3),(51,3),(52,3),(53,3),
            (41,4),(42,4),(43,4),(44,4),(45,4),(46,4),(47,4),(48,4),(49,4),(50,4),(51,4),(52,4),(53,4),(54,4),
            (42,5),(43,5),(44,5),(45,5),(46,5),(47,5),(48,5),(49,5),(50,5),(51,5),(52,5),(53,5),(54,5),(55,5),
            (43,6),(44,6),(45,6),(46,6),(47,6),(48,6),(49,6),(50,6),(51,6),(52,6),(53,6),(54,6),(55,6),(56,6),
            (44,7),(45,7),(46,7),(47,7),(48,7),(49,7),(50,7),(51,7),(52,7),(53,7),(54,7),(55,7),
            (45,8),(46,8),(47,8),(48,8),(49,8),(50,8),(51,8),(52,8),(53,8),(54,8),
            (47,9),(48,9),(49,9),(50,9),(51,9),(52,9),(53,9),
            (48,10),(49,10),(50,10),(51,10),(52,10),
        ]

        # Australia
        au_coords = [
            (55,13),(56,13),(57,13),(58,13),(59,13),(60,13),
            (54,14),(55,14),(56,14),(57,14),(58,14),(59,14),(60,14),(61,14),
            (55,15),(56,15),(57,15),(58,15),(59,15),(60,15),(61,15),
            (56,16),(57,16),(58,16),(59,16),(60,16),
            (57,17),(58,17),(59,17),
        ]

        all_coords = na_coords + sa_coords + eu_coords + af_coords + as_coords + au_coords

        for x, y in all_coords:
            scaled_x = int(x * sx)
            scaled_y = int(y * sy)
            coords.append((scaled_x, scaled_y))

        return coords

    def get_all_locations(self):
        """Get all cached locations."""
        with self._lock:
            return dict(self._cache)
