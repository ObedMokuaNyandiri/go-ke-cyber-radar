"""
.GO.KE Cyber-Surface Radar — Helper Utilities
===============================================
Common utility functions used throughout the application.
"""

import json
import hashlib
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import (
    RISK_THRESHOLDS, RiskLevel, RISK_COLORS, RISK_EMOJIS,
    KNOWN_PORTS, DATABASE_PORTS, ADMIN_PORTS, DANGEROUS_PORTS,
    KENYA_LOCATIONS,
)


# ── Data Loading ──────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / "data"


def load_json(filename: str) -> Dict[str, Any]:
    """Load a JSON file from the data directory."""
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def load_domains() -> List[Dict[str, str]]:
    """Load the .go.ke domain database."""
    data = load_json("go_ke_domains.json")
    return data.get("domains", [])


def load_ministry_mapping() -> Dict[str, Any]:
    """Load the ministry mapping data."""
    data = load_json("ministry_mapping.json")
    return data.get("ministries", {})


def load_vulns() -> Dict[str, Any]:
    """Load the common vulnerabilities database."""
    return load_json("common_vulns.json")


# ── CSS Loading ───────────────────────────────────────────────────────────────
STYLES_DIR = Path(__file__).parent.parent / "styles"


def load_css() -> str:
    """Load the custom CSS theme."""
    css_file = STYLES_DIR / "cyber_theme.css"
    if css_file.exists():
        return css_file.read_text(encoding="utf-8")
    return ""


# ── Risk Classification ──────────────────────────────────────────────────────
def classify_risk(score: float) -> RiskLevel:
    """Classify a numeric risk score into a RiskLevel."""
    for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
        if score >= RISK_THRESHOLDS[level]:
            return level
    return RiskLevel.INFO


def risk_color(level: RiskLevel) -> str:
    """Get the CSS color for a risk level."""
    return RISK_COLORS.get(level, "#64748b")


def risk_emoji(level: RiskLevel) -> str:
    """Get the emoji for a risk level."""
    return RISK_EMOJIS.get(level, "[i]")


# ── Port Classification ──────────────────────────────────────────────────────
def classify_port(port: int) -> str:
    """Classify a port as database, admin, dangerous, or standard."""
    if port in DATABASE_PORTS:
        return "database"
    if port in ADMIN_PORTS:
        return "admin"
    if port in DANGEROUS_PORTS:
        return "dangerous"
    return "standard"


def port_name(port: int) -> str:
    """Get the human-readable name for a port."""
    return KNOWN_PORTS.get(port, f"Port-{port}")


# ── Formatting ────────────────────────────────────────────────────────────────
def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format a datetime as a short timestamp string."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_relative_time(dt: datetime) -> str:
    """Format a datetime as relative time (e.g., '3 days ago', 'in 2 months')."""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - now

    if delta.total_seconds() < 0:
        # Past
        abs_delta = abs(delta)
        if abs_delta.days > 365:
            return f"{abs_delta.days // 365}y ago"
        if abs_delta.days > 30:
            return f"{abs_delta.days // 30}mo ago"
        if abs_delta.days > 0:
            return f"{abs_delta.days}d ago"
        if abs_delta.seconds > 3600:
            return f"{abs_delta.seconds // 3600}h ago"
        if abs_delta.seconds > 60:
            return f"{abs_delta.seconds // 60}m ago"
        return "just now"
    else:
        # Future
        if delta.days > 365:
            return f"in {delta.days // 365}y"
        if delta.days > 30:
            return f"in {delta.days // 30}mo"
        if delta.days > 0:
            return f"in {delta.days}d"
        if delta.seconds > 3600:
            return f"in {delta.seconds // 3600}h"
        return f"in {delta.seconds // 60}m"


def truncate(text: str, max_len: int = 50) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


# ── Geolocation ───────────────────────────────────────────────────────────────
def assign_location(domain: str) -> Dict[str, float]:
    """Assign a semi-random Kenya location to a domain (deterministic per domain)."""
    # Use domain hash for deterministic but varied placement
    hash_val = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    locations = list(KENYA_LOCATIONS.values())
    base = locations[hash_val % len(locations)]
    # Add slight random offset based on hash for spread
    offset_lat = ((hash_val % 1000) / 1000 - 0.5) * 0.15
    offset_lon = ((hash_val % 997) / 997 - 0.5) * 0.15
    return {
        "lat": base["lat"] + offset_lat,
        "lon": base["lon"] + offset_lon,
    }


# ── Metric Card HTML ─────────────────────────────────────────────────────────
def metric_card_html(value: str, label: str, color_class: str = "cyan",
                     icon: str = "", delta: str = "") -> str:
    """Generate HTML for a styled metric card."""
    delta_html = ""
    if delta:
        delta_html = f'<div class="metric-delta">{delta}</div>'

    return f"""
    <div class="metric-card metric-{color_class}">
        <div class="metric-value">{icon} {value}</div>
        <div class="metric-label">{label}</div>
        {delta_html}
    </div>
    """


# ── Threat Feed Item HTML ────────────────────────────────────────────────────
def threat_item_html(timestamp: str, level: str, domain: str, message: str) -> str:
    """Generate HTML for a single threat feed item."""
    level_lower = level.lower()
    return f"""
    <div class="threat-item {level_lower}">
        <span class="threat-timestamp">{timestamp}</span>
        <span class="threat-badge badge-{level_lower}">{level}</span>
        <strong style="color: var(--text-primary); margin-left: 4px;">{domain}</strong>
        <span style="color: var(--text-secondary);">— {message}</span>
    </div>
    """


# ── Demo Data Generator ──────────────────────────────────────────────────────
def generate_demo_scan_results() -> List[Dict[str, Any]]:
    """Generate realistic demo scan results for demonstration mode."""
    domains = load_domains()
    results = []
    now = datetime.now(timezone.utc)
    random.seed(42)  # Deterministic for consistency

    demo_scenarios = [
        # (domain_idx, ssl_status, ssl_expiry_days, open_ports, server, missing_headers, findings)
        (0, "valid", 245, [80, 443], "nginx/1.18", 2, []),
        (1, "expired", -45, [80, 443, 8080], "Apache/2.4.6", 5, ["Exposed admin panel on :8080"]),
        (2, "valid", 120, [80, 443], "nginx/1.24", 1, []),
        (3, "expiring", 18, [80, 443, 22], "Apache/2.4.29", 4, ["SSH exposed to internet"]),
        (4, "valid", 300, [80, 443], "nginx/1.22", 0, []),
        (5, "expired", -120, [80, 443, 3306], "Apache/2.2", 6, ["MySQL database exposed on port 3306", "End-of-life Apache version"]),
        (6, "valid", 90, [80, 443, 22], "nginx/1.18", 3, []),
        (7, "missing", 0, [80], "IIS/8.5", 7, ["No HTTPS configured", "All security headers missing"]),
        (8, "valid", 200, [80, 443], "Apache/2.4.58", 1, []),
        (9, "expiring", 25, [80, 443, 8443, 9090], "Apache/2.4.18", 4, ["Admin panel on :9090", "Outdated Apache"]),
        (10, "valid", 180, [80, 443], "nginx/1.24", 0, []),
        (11, "expired", -30, [80, 443, 21], "Apache/2.4.10", 5, ["FTP service exposed"]),
        (12, "valid", 150, [80, 443], "nginx/1.22", 2, []),
        (13, "valid", 340, [80, 443], "Apache/2.4.58", 1, []),
        (14, "expiring", 12, [80, 443, 5432], "nginx/1.14", 3, ["PostgreSQL exposed on port 5432", "Certificate expiring in 12 days"]),
        (15, "valid", 290, [80, 443], "Apache/2.4.58", 0, []),
        (16, "expired", -200, [80], "Apache/2.2", 7, ["No HTTPS", "End-of-life server", "All security headers missing"]),
        (17, "valid", 100, [80, 443], "nginx/1.24", 2, []),
        (18, "valid", 250, [80, 443, 22], "Apache/2.4.52", 1, []),
        (19, "expiring", 28, [80, 443], "nginx/1.18", 3, []),
        (20, "valid", 200, [80, 443], "Apache/2.4.58", 0, []),
        (21, "valid", 180, [80, 443], "nginx/1.22", 1, []),
        (22, "missing", 0, [80, 8080], "IIS/7.5", 7, ["No HTTPS", "End-of-life IIS", "Admin on :8080"]),
        (23, "valid", 320, [80, 443], "Apache/2.4.58", 0, []),
        (24, "valid", 150, [80, 443], "nginx/1.24", 1, []),
        (25, "expiring", 22, [80, 443, 22, 3389], "Apache/2.4.29", 4, ["RDP exposed on port 3389", "SSH exposed"]),
        (26, "valid", 280, [80, 443], "nginx/1.22", 2, []),
        (27, "expired", -60, [80, 443], "Apache/2.4.6", 5, ["Expired SSL certificate"]),
        (28, "valid", 200, [80, 443], "nginx/1.24", 0, []),
        (29, "valid", 100, [80, 443], "Apache/2.4.52", 1, []),
        (30, "valid", 350, [80, 443], "nginx/1.24", 0, []),
        (31, "expiring", 8, [80, 443, 27017], "Apache/2.4.18", 5, ["MongoDB exposed on port 27017!", "Certificate expires in 8 days"]),
        (32, "valid", 180, [80, 443], "nginx/1.22", 2, []),
        (33, "valid", 290, [80, 443], "Apache/2.4.58", 1, []),
        (34, "valid", 150, [80, 443], "nginx/1.24", 0, []),
        (35, "valid", 220, [80, 443], "Apache/2.4.52", 1, []),
        (36, "expired", -15, [80, 443, 9200], "nginx/1.16", 4, ["Elasticsearch exposed on port 9200", "SSL just expired"]),
        (37, "valid", 300, [80, 443], "Apache/2.4.58", 0, []),
        (38, "valid", 160, [80, 443], "nginx/1.24", 1, []),
        (39, "expiring", 15, [80, 443], "Apache/2.4.29", 3, []),
    ]

    for i, scenario in enumerate(demo_scenarios):
        if i >= len(domains):
            break
        dom_idx, ssl_status, ssl_days, ports, server, missing_h, findings = scenario
        domain_info = domains[dom_idx]

        # Calculate SSL expiry date
        ssl_expiry = None
        if ssl_status != "missing":
            ssl_expiry = (now + timedelta(days=ssl_days)).isoformat()

        # Build scan result
        location = assign_location(domain_info["domain"])
        result = {
            "domain": domain_info["domain"],
            "name": domain_info["name"],
            "ministry": domain_info["ministry"],
            "category": domain_info.get("category", "governance"),
            "ip": f"197.{random.randint(136, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "location": location,
            "scan_time": now.isoformat(),
            "ssl": {
                "status": ssl_status,
                "expiry": ssl_expiry,
                "days_remaining": ssl_days if ssl_status != "missing" else None,
                "issuer": "Let's Encrypt" if ssl_status != "missing" else None,
                "protocol": "TLSv1.2" if ssl_status != "missing" else None,
            },
            "ports": [
                {"port": p, "service": port_name(p), "type": classify_port(p)}
                for p in ports
            ],
            "server": {
                "banner": server,
                "technology": server.split("/")[0] if "/" in server else server,
                "version": server.split("/")[1] if "/" in server else "unknown",
            },
            "headers": {
                "missing_count": missing_h,
                "total": 7,
                "score": round((7 - missing_h) / 7 * 100),
            },
            "findings": findings,
            "risk_score": 0,  # Will be calculated
            "risk_level": "INFO",
        }

        # Calculate risk score
        score = 0
        if ssl_status == "expired":
            score += 30
        elif ssl_status == "expiring" and ssl_days <= 30:
            score += 15
        elif ssl_status == "missing":
            score += 25

        for p_info in result["ports"]:
            if p_info["type"] == "database":
                score += 20
            elif p_info["type"] == "dangerous":
                score += 15
            elif p_info["type"] == "admin":
                score += 12

        score += missing_h * 5

        # Server version check
        if "2.2" in server or "7.5" in server or "7.0" in server:
            score += 30
        elif any(v in server for v in ["2.4.6", "2.4.10", "2.4.18", "1.14", "1.16"]):
            score += 20

        score = min(score, 100)
        level = classify_risk(score)
        result["risk_score"] = score
        result["risk_level"] = level.value

        results.append(result)

    return results
