"""
.GO.KE Cyber-Surface Radar — Risk Scoring Engine
==================================================
Calculates comprehensive risk scores for individual assets
and the overall national cyber-attack surface.
"""

from typing import Any, Dict, List

from config import RiskLevel, RISK_WEIGHTS, RISK_THRESHOLDS
from utils.helpers import classify_risk


def calculate_asset_risk(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate a detailed risk breakdown for a single scanned asset.

    Returns:
        Dict with overall score, level, and per-factor breakdown
    """
    breakdown = {
        "ssl": {"score": 0, "max": 30, "factors": []},
        "ports": {"score": 0, "max": 45, "factors": []},
        "headers": {"score": 0, "max": 35, "factors": []},
        "server": {"score": 0, "max": 30, "factors": []},
        "config": {"score": 0, "max": 15, "factors": []},
    }

    # ── SSL Risk ──────────────────────────────────────────────────────────
    ssl = scan_result.get("ssl", {})
    ssl_status = ssl.get("status", "unknown")

    if ssl_status == "expired":
        breakdown["ssl"]["score"] += RISK_WEIGHTS["ssl_expired"]
        breakdown["ssl"]["factors"].append("SSL certificate expired")
    elif ssl_status == "missing":
        breakdown["ssl"]["score"] += RISK_WEIGHTS["ssl_missing"]
        breakdown["ssl"]["factors"].append("No SSL/TLS certificate")
    elif ssl_status == "expiring":
        days = ssl.get("days_remaining", 999)
        if days <= 30:
            breakdown["ssl"]["score"] += RISK_WEIGHTS["ssl_expiring_soon"]
            breakdown["ssl"]["factors"].append(f"SSL expires in {days} days")
        elif days <= 90:
            breakdown["ssl"]["score"] += RISK_WEIGHTS["ssl_expiring_warning"]
            breakdown["ssl"]["factors"].append(f"SSL expires in {days} days")

    if ssl.get("self_signed"):
        breakdown["ssl"]["score"] += RISK_WEIGHTS["ssl_self_signed"]
        breakdown["ssl"]["factors"].append("Self-signed certificate")

    # ── Port Risk ─────────────────────────────────────────────────────────
    for port_info in scan_result.get("ports", []):
        ptype = port_info.get("type", "standard")
        port = port_info.get("port", 0)
        service = port_info.get("service", "unknown")

        if ptype == "database":
            breakdown["ports"]["score"] += RISK_WEIGHTS["port_database"]
            breakdown["ports"]["factors"].append(f"Database exposed: {port}/{service}")
        elif ptype == "dangerous":
            breakdown["ports"]["score"] += RISK_WEIGHTS["port_critical"]
            breakdown["ports"]["factors"].append(f"Dangerous port open: {port}/{service}")
        elif ptype == "admin":
            breakdown["ports"]["score"] += RISK_WEIGHTS["port_admin"]
            breakdown["ports"]["factors"].append(f"Admin panel exposed: {port}/{service}")

    # ── Header Risk ───────────────────────────────────────────────────────
    missing = scan_result.get("headers", {}).get("missing_count", 0)
    if missing > 0:
        header_risk = missing * RISK_WEIGHTS["header_missing"]
        breakdown["headers"]["score"] += min(header_risk, breakdown["headers"]["max"])
        breakdown["headers"]["factors"].append(f"{missing}/7 security headers missing")

    # ── Server Risk ───────────────────────────────────────────────────────
    server = scan_result.get("server", {})
    if server.get("eol"):
        breakdown["server"]["score"] += RISK_WEIGHTS["server_eol"]
        breakdown["server"]["factors"].append(f"End-of-life server: {server.get('banner', 'unknown')}")
    elif server.get("status") == "outdated":
        breakdown["server"]["score"] += RISK_WEIGHTS["server_outdated"]
        breakdown["server"]["factors"].append(f"Outdated server: {server.get('banner', 'unknown')}")

    # ── Configuration Risk ────────────────────────────────────────────────
    if not scan_result.get("headers", {}).get("https_redirect", True):
        breakdown["config"]["score"] += RISK_WEIGHTS["http_no_redirect"]
        breakdown["config"]["factors"].append("HTTP does not redirect to HTTPS")

    # ── Calculate Total ───────────────────────────────────────────────────
    total_score = sum(cat["score"] for cat in breakdown.values())
    total_score = min(total_score, 100)

    return {
        "total_score": total_score,
        "level": classify_risk(total_score),
        "breakdown": breakdown,
        "top_risks": _get_top_risks(breakdown),
    }


def _get_top_risks(breakdown: Dict) -> List[str]:
    """Extract the top risk factors from the breakdown."""
    all_factors = []
    for category, data in breakdown.items():
        if data["score"] > 0:
            for factor in data["factors"]:
                all_factors.append({"category": category, "factor": factor, "score": data["score"]})

    all_factors.sort(key=lambda x: x["score"], reverse=True)
    return [f["factor"] for f in all_factors[:5]]


def calculate_national_risk(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate the overall national cyber-risk score from all scan results.
    """
    if not results:
        return {
            "score": 0,
            "level": RiskLevel.INFO,
            "grade": "N/A",
            "summary": "No scan data available",
        }

    scores = [r.get("risk_score", 0) for r in results]
    avg_score = sum(scores) / len(scores)

    # Weight critical assets higher
    critical_categories = {"executive", "security", "finance"}
    weighted_scores = []
    for r in results:
        category = r.get("category", "governance")
        weight = 1.5 if category in critical_categories else 1.0
        weighted_scores.append(r.get("risk_score", 0) * weight)

    weighted_avg = sum(weighted_scores) / sum(
        1.5 if r.get("category", "") in critical_categories else 1.0
        for r in results
    )

    # National score is a blend of average and weighted
    national_score = round(weighted_avg * 0.6 + avg_score * 0.4)
    national_score = min(national_score, 100)

    level = classify_risk(national_score)

    # Determine grade
    if national_score <= 15:
        grade = "A"
    elif national_score <= 30:
        grade = "B"
    elif national_score <= 50:
        grade = "C"
    elif national_score <= 70:
        grade = "D"
    else:
        grade = "F"

    # Generate summary
    critical_count = sum(1 for r in results if r.get("risk_level") == "CRITICAL")
    high_count = sum(1 for r in results if r.get("risk_level") == "HIGH")

    if critical_count > 0:
        summary = f"{critical_count} critical-risk assets require immediate attention"
    elif high_count > 0:
        summary = f"{high_count} high-risk assets detected across the infrastructure"
    elif national_score > 40:
        summary = "Multiple medium-risk issues detected — remediation recommended"
    else:
        summary = "Infrastructure posture is within acceptable risk parameters"

    return {
        "score": national_score,
        "level": level,
        "grade": grade,
        "summary": summary,
        "avg_score": round(avg_score, 1),
        "max_score": max(scores),
        "min_score": min(scores),
        "critical_assets": critical_count,
        "high_assets": high_count,
    }


def calculate_ministry_risks(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Calculate risk scores grouped by ministry.
    """
    ministry_data = {}

    for r in results:
        ministry = r.get("ministry", "Unknown")
        if ministry not in ministry_data:
            ministry_data[ministry] = {
                "domains": [],
                "scores": [],
                "findings": [],
                "ssl_issues": 0,
                "exposed_ports": 0,
            }

        ministry_data[ministry]["domains"].append(r.get("domain", ""))
        ministry_data[ministry]["scores"].append(r.get("risk_score", 0))
        ministry_data[ministry]["findings"].extend(r.get("findings", []))

        ssl_status = r.get("ssl", {}).get("status", "valid")
        if ssl_status in ("expired", "expiring", "missing"):
            ministry_data[ministry]["ssl_issues"] += 1

        for port in r.get("ports", []):
            if port.get("type") in ("database", "dangerous", "admin"):
                ministry_data[ministry]["exposed_ports"] += 1

    # Calculate averages and levels
    for ministry, data in ministry_data.items():
        scores = data["scores"]
        avg = round(sum(scores) / len(scores), 1) if scores else 0
        data["avg_risk"] = avg
        data["max_risk"] = max(scores) if scores else 0
        data["risk_level"] = classify_risk(avg)
        data["domain_count"] = len(data["domains"])
        data["finding_count"] = len(data["findings"])

    return ministry_data
