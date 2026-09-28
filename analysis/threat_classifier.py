"""
.GO.KE Cyber-Surface Radar — Threat Classifier
=================================================
Classifies and categorizes findings into actionable threat intelligence.
"""

from typing import Any, Dict, List
from datetime import datetime, timezone

from config import RiskLevel, RISK_COLORS, RISK_EMOJIS
from utils.helpers import classify_risk, format_timestamp


# ── Threat Categories ─────────────────────────────────────────────────────────
THREAT_CATEGORIES = {
    "ssl_expired": {
        "category": "Certificate Security",
        "icon": "[U]",
        "remediation": "Renew the SSL certificate immediately. Consider using automated renewal with Let's Encrypt / Certbot.",
    },
    "ssl_expiring": {
        "category": "Certificate Security",
        "icon": "[T]",
        "remediation": "Renew the SSL certificate before expiry. Implement automated renewal monitoring.",
    },
    "ssl_missing": {
        "category": "Certificate Security",
        "icon": "[X]",
        "remediation": "Deploy an SSL/TLS certificate. Use Let's Encrypt for free certificates.",
    },
    "ssl_self_signed": {
        "category": "Certificate Security",
        "icon": "[!]",
        "remediation": "Replace with a certificate from a trusted Certificate Authority.",
    },
    "exposed_database": {
        "category": "Data Exposure",
        "icon": "[D]",
        "remediation": "Restrict database access to internal networks. Use firewall rules and VPN.",
    },
    "dangerous_port": {
        "category": "Network Security",
        "icon": "[P]",
        "remediation": "Close or restrict the dangerous service. Use VPN for remote access.",
    },
    "admin_panel": {
        "category": "Access Control",
        "icon": "[K]",
        "remediation": "Restrict admin panel access by IP whitelist. Enable 2FA.",
    },
    "missing_headers": {
        "category": "Web Security",
        "icon": "[C]",
        "remediation": "Configure all recommended security headers in the web server.",
    },
    "outdated_server": {
        "category": "Patch Management",
        "icon": "[V]",
        "remediation": "Update the server software to the latest stable version.",
    },
    "eol_server": {
        "category": "Patch Management",
        "icon": "[S]",
        "remediation": "URGENT: Migrate to a supported software version. No security patches available.",
    },
    "no_https_redirect": {
        "category": "Transport Security",
        "icon": "[R]",
        "remediation": "Configure HTTP to HTTPS redirect in the web server or load balancer.",
    },
}


def classify_threats(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Classify all findings across scan results into structured threats.

    Returns a list of threat objects sorted by severity.
    """
    threats = []
    now = datetime.now(timezone.utc)

    for result in scan_results:
        domain = result.get("domain", "unknown")
        ministry = result.get("ministry", "Unknown")

        # SSL threats
        ssl = result.get("ssl", {})
        ssl_status = ssl.get("status", "unknown")

        if ssl_status == "expired":
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="ssl_expired",
                level=RiskLevel.CRITICAL,
                title=f"Expired SSL Certificate",
                detail=f"Certificate expired {abs(ssl.get('days_remaining', 0))} days ago",
                timestamp=now,
            ))
        elif ssl_status == "expiring":
            days = ssl.get("days_remaining", 0)
            level = RiskLevel.HIGH if days <= 14 else RiskLevel.MEDIUM
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="ssl_expiring",
                level=level,
                title=f"SSL Certificate Expiring Soon",
                detail=f"Certificate expires in {days} days",
                timestamp=now,
            ))
        elif ssl_status == "missing":
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="ssl_missing",
                level=RiskLevel.HIGH,
                title=f"No SSL/TLS Certificate",
                detail="Site is served over unencrypted HTTP",
                timestamp=now,
            ))

        if ssl.get("self_signed"):
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="ssl_self_signed",
                level=RiskLevel.MEDIUM,
                title=f"Self-Signed Certificate",
                detail="Certificate not issued by a trusted authority",
                timestamp=now,
            ))

        # Port threats
        for port_info in result.get("ports", []):
            ptype = port_info.get("type", "standard")
            port = port_info.get("port", 0)
            service = port_info.get("service", "unknown")

            if ptype == "database":
                threats.append(_make_threat(
                    domain=domain,
                    ministry=ministry,
                    threat_type="exposed_database",
                    level=RiskLevel.CRITICAL,
                    title=f"Exposed Database: {service}",
                    detail=f"Port {port} ({service}) is directly accessible from the internet",
                    timestamp=now,
                ))
            elif ptype == "dangerous":
                threats.append(_make_threat(
                    domain=domain,
                    ministry=ministry,
                    threat_type="dangerous_port",
                    level=RiskLevel.HIGH,
                    title=f"Dangerous Service: {service}",
                    detail=f"Port {port} ({service}) is exposed to the internet",
                    timestamp=now,
                ))
            elif ptype == "admin":
                threats.append(_make_threat(
                    domain=domain,
                    ministry=ministry,
                    threat_type="admin_panel",
                    level=RiskLevel.MEDIUM,
                    title=f"Admin Panel Exposed: {service}",
                    detail=f"Port {port} ({service}) accessible externally",
                    timestamp=now,
                ))

        # Header threats
        missing_count = result.get("headers", {}).get("missing_count", 0)
        if missing_count >= 5:
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="missing_headers",
                level=RiskLevel.MEDIUM,
                title=f"Critical Security Headers Missing",
                detail=f"{missing_count}/7 security headers not configured",
                timestamp=now,
            ))
        elif missing_count >= 3:
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="missing_headers",
                level=RiskLevel.LOW,
                title=f"Security Headers Missing",
                detail=f"{missing_count}/7 security headers not configured",
                timestamp=now,
            ))

        # Server threats
        server = result.get("server", {})
        if server.get("eol"):
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="eol_server",
                level=RiskLevel.CRITICAL,
                title=f"End-of-Life Server Software",
                detail=f"{server.get('banner', 'Unknown')} — no security patches available",
                timestamp=now,
            ))
        elif server.get("status") == "outdated":
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="outdated_server",
                level=RiskLevel.MEDIUM,
                title=f"Outdated Server Software",
                detail=f"{server.get('banner', 'Unknown')} — update recommended",
                timestamp=now,
            ))

        # HTTPS redirect
        if not result.get("headers", {}).get("https_redirect", True):
            threats.append(_make_threat(
                domain=domain,
                ministry=ministry,
                threat_type="no_https_redirect",
                level=RiskLevel.LOW,
                title=f"No HTTPS Redirect",
                detail="HTTP traffic is not automatically redirected to HTTPS",
                timestamp=now,
            ))

    # Sort by severity (CRITICAL first)
    severity_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4,
    }
    threats.sort(key=lambda t: severity_order.get(t["level_enum"], 4))

    return threats


def _make_threat(
    domain: str,
    ministry: str,
    threat_type: str,
    level: RiskLevel,
    title: str,
    detail: str,
    timestamp: datetime,
) -> Dict[str, Any]:
    """Create a structured threat object."""
    category_info = THREAT_CATEGORIES.get(threat_type, {})
    return {
        "domain": domain,
        "ministry": ministry,
        "type": threat_type,
        "category": category_info.get("category", "General"),
        "icon": category_info.get("icon", "[!]"),
        "level": level.value,
        "level_enum": level,
        "color": RISK_COLORS.get(level, "#64748b"),
        "emoji": RISK_EMOJIS.get(level, "[i]"),
        "title": title,
        "detail": detail,
        "remediation": category_info.get("remediation", "Review and remediate."),
        "timestamp": format_timestamp(timestamp),
    }


def get_threat_summary(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize threats by category and severity."""
    by_level = {}
    by_category = {}
    by_ministry = {}

    for t in threats:
        level = t["level"]
        category = t["category"]
        ministry = t["ministry"]

        by_level[level] = by_level.get(level, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        by_ministry[ministry] = by_ministry.get(ministry, 0) + 1

    return {
        "total": len(threats),
        "by_level": by_level,
        "by_category": by_category,
        "by_ministry": dict(sorted(by_ministry.items(), key=lambda x: x[1], reverse=True)),
        "top_category": max(by_category, key=by_category.get) if by_category else "None",
    }
