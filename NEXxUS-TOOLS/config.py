"""
NetVision Configuration
"""

# ─── Network Settings ────────────────────────────────────────────────
SCAN_INTERVAL = 5          # Seconds between device scans
SPEED_INTERVAL = 2         # Seconds between speed measurements
TRAFFIC_INTERVAL = 1       # Seconds between traffic captures
GEO_CACHE_TTL = 3600       # Geolocation cache TTL in seconds

# ─── Interface Settings ──────────────────────────────────────────────
DEFAULT_INTERFACE = None    # Auto-detect if None
SUBNET_MASK = "/24"         # Default subnet mask for scanning

# ─── Geolocation API ─────────────────────────────────────────────────
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
GEO_API_RATE_LIMIT = 45    # Max requests per minute (free tier)

# ─── Display Settings ────────────────────────────────────────────────
MAX_DEVICES_DISPLAY = 20
MAX_TRAFFIC_LOG = 100
MAP_WIDTH = 80
MAP_HEIGHT = 24

# ─── Colors (Rich markup) ────────────────────────────────────────────
COLORS = {
    "header": "bold bright_cyan",
    "device_online": "bright_green",
    "device_offline": "dim red",
    "speed_high": "bright_red",
    "speed_medium": "bright_yellow",
    "speed_low": "bright_green",
    "alert": "bold bright_red",
    "info": "bright_blue",
    "geo_marker": "bright_magenta",
    "traffic_dns": "bright_cyan",
    "traffic_http": "bright_yellow",
    "traffic_https": "bright_green",
    "border": "bright_blue",
}
