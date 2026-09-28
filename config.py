"""
.GO.KE Cyber-Surface Radar — Configuration
============================================
Central configuration for the national cyber-attack surface dashboard.
All constants, API settings, and classification rules live here.
"""

import os
from enum import Enum
from typing import Dict, Set

from dotenv import load_dotenv
load_dotenv()

# ── API Configuration ─────────────────────────────────────────────────────────
SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
SHODAN_BASE_URL: str = "https://api.shodan.io"

# ── Application Settings ─────────────────────────────────────────────────────
APP_TITLE: str = ".GO.KE Cyber-Surface Radar"
APP_SUBTITLE: str = "National Cyber-Attack Surface Intelligence"
APP_ICON: str = "◆"
APP_VERSION: str = "1.0.0"
SCAN_DOMAIN: str = "go.ke"
SCAN_TIMEOUT: int = 10  # seconds
MAX_CONCURRENT_SCANS: int = 5
SSL_CHECK_TIMEOUT: int = 8
HTTP_CHECK_TIMEOUT: int = 8
DNS_TIMEOUT: int = 5


# ── Risk Classification ──────────────────────────────────────────────────────
class RiskLevel(Enum):
    """Threat severity classification levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


RISK_THRESHOLDS: Dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 80,
    RiskLevel.HIGH: 60,
    RiskLevel.MEDIUM: 40,
    RiskLevel.LOW: 20,
    RiskLevel.INFO: 0,
}

RISK_COLORS: Dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "#ff003c",
    RiskLevel.HIGH: "#ff6b35",
    RiskLevel.MEDIUM: "#ffaa00",
    RiskLevel.LOW: "#00f0ff",
    RiskLevel.INFO: "#64748b",
}

RISK_EMOJIS: Dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "[!]",
    RiskLevel.HIGH: "[!]",
    RiskLevel.MEDIUM: "[-]",
    RiskLevel.LOW: "[v]",
    RiskLevel.INFO: "[i]",
}


# ── Port Classifications ─────────────────────────────────────────────────────
KNOWN_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2082: "cPanel",
    2083: "cPanel SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt-2",
    9090: "Admin Panel",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

DATABASE_PORTS: Set[int] = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
ADMIN_PORTS: Set[int] = {2082, 2083, 8080, 8443, 9090}
DANGEROUS_PORTS: Set[int] = {23, 445, 3389, 5900}
ENCRYPTED_PORTS: Set[int] = {443, 993, 995, 8443, 587}

# ── Security Headers ─────────────────────────────────────────────────────────
SECURITY_HEADERS: list = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

HEADER_DESCRIPTIONS: Dict[str, str] = {
    "Strict-Transport-Security": "Forces HTTPS connections, preventing downgrade attacks",
    "Content-Security-Policy": "Controls resource loading, mitigates XSS attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
    "X-Frame-Options": "Protects against clickjacking attacks",
    "X-XSS-Protection": "Enables browser XSS filtering",
    "Referrer-Policy": "Controls referrer information sent with requests",
    "Permissions-Policy": "Controls browser feature access (camera, mic, etc.)",
}


# ── Risk Scoring Weights ─────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "ssl_expired": 30,
    "ssl_expiring_soon": 15,    # < 30 days
    "ssl_expiring_warning": 8,  # < 90 days
    "ssl_weak_cipher": 10,
    "ssl_self_signed": 12,
    "ssl_missing": 25,
    "port_critical": 15,        # per dangerous port
    "port_database": 20,        # per exposed database
    "port_admin": 12,           # per exposed admin panel
    "server_outdated": 20,
    "server_eol": 30,           # end of life
    "header_missing": 5,        # per missing header
    "exposed_directory": 10,
    "dns_zone_transfer": 25,
    "dns_dangling_cname": 15,
    "http_no_redirect": 8,      # HTTP not redirecting to HTTPS
}


# ── Design System ────────────────────────────────────────────────────────────
COLORS = {
    "bg_primary": "#0a0e17",
    "bg_secondary": "#111827",
    "bg_elevated": "#1a2332",
    "bg_card": "#0f1923",
    "border_subtle": "#1e293b",
    "border_glow": "#00f0ff33",
    "accent_cyan": "#00f0ff",
    "accent_green": "#00ff88",
    "accent_amber": "#ffaa00",
    "accent_red": "#ff003c",
    "accent_purple": "#a855f7",
    "accent_blue": "#3b82f6",
    "text_primary": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
}


# ── Kenya Geographic Data ────────────────────────────────────────────────────
KENYA_CENTER = {"lat": -1.2921, "lon": 36.8219}  # Nairobi
KENYA_ZOOM = 6

# Major data center / hosting locations in Kenya
KENYA_LOCATIONS = {
    "Nairobi": {"lat": -1.2921, "lon": 36.8219},
    "Mombasa": {"lat": -4.0435, "lon": 39.6682},
    "Kisumu": {"lat": -0.0917, "lon": 34.7680},
    "Nakuru": {"lat": -0.3031, "lon": 36.0800},
    "Eldoret": {"lat": 0.5143, "lon": 35.2698},
    "Naivasha": {"lat": -0.7172, "lon": 36.4310},
    "Thika": {"lat": -1.0396, "lon": 37.0900},
    "Nyeri": {"lat": -0.4197, "lon": 36.9511},
    "Machakos": {"lat": -1.5177, "lon": 37.2634},
    "Garissa": {"lat": -0.4532, "lon": 39.6461},
}


# ── Server Version Patterns (for outdated detection) ─────────────────────────
OUTDATED_SERVERS = {
    "Apache/2.2": {"status": "eol", "eol_date": "2018-01-01"},
    "Apache/2.4.1": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.6": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.7": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.10": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.18": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.25": {"status": "outdated", "latest": "2.4.58"},
    "Apache/2.4.29": {"status": "outdated", "latest": "2.4.58"},
    "nginx/1.14": {"status": "outdated", "latest": "1.25"},
    "nginx/1.16": {"status": "outdated", "latest": "1.25"},
    "nginx/1.18": {"status": "outdated", "latest": "1.25"},
    "IIS/7.0": {"status": "eol", "eol_date": "2015-01-01"},
    "IIS/7.5": {"status": "eol", "eol_date": "2020-01-14"},
    "IIS/8.0": {"status": "eol", "eol_date": "2023-10-10"},
    "IIS/8.5": {"status": "outdated", "latest": "10.0"},
    "PHP/5": {"status": "eol", "eol_date": "2018-12-31"},
    "PHP/7.0": {"status": "eol", "eol_date": "2019-01-01"},
    "PHP/7.1": {"status": "eol", "eol_date": "2019-12-01"},
    "PHP/7.2": {"status": "eol", "eol_date": "2020-11-30"},
    "PHP/7.3": {"status": "eol", "eol_date": "2021-12-06"},
    "PHP/7.4": {"status": "eol", "eol_date": "2022-11-28"},
    "OpenSSL/1.0": {"status": "eol", "eol_date": "2020-01-01"},
    "OpenSSL/1.1.0": {"status": "eol", "eol_date": "2019-09-11"},
}
