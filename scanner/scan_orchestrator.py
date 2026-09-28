"""
.GO.KE Cyber-Surface Radar — Scan Orchestrator
=================================================
Coordinates all scanning modules to produce unified results.
Manages scan state, progress tracking, and result aggregation.
"""

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from config import RiskLevel
from utils.helpers import (
    load_domains, assign_location, classify_risk, classify_port, port_name,
)
from scanner.ssl_checker import check_ssl, get_ssl_grade
from scanner.dns_enumerator import resolve_domain
from scanner.header_analyzer import analyze_headers, check_server_version
from scanner.shodan_scanner import ShodanScanner


class ScanOrchestrator:
    """
    Orchestrates all scanning modules to produce comprehensive
    attack surface assessment results.
    """

    def __init__(self, shodan_api_key: Optional[str] = None):
        self.shodan = ShodanScanner(api_key=shodan_api_key)
        self.domains = load_domains()
        self.results: List[Dict[str, Any]] = []
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None
        self.is_scanning = False
        self.progress = 0.0
        self.current_domain = ""
        self.errors: List[str] = []

    def scan_all(
        self,
        domains: Optional[List[Dict]] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run a full scan across all domains.

        Args:
            domains: Optional list of domain dicts to scan (defaults to all known)
            progress_callback: Optional callback(progress_pct, current_domain)

        Returns:
            List of unified scan results
        """
        self.is_scanning = True
        self.scan_start = datetime.now(timezone.utc)
        self.results = []
        self.errors = []

        target_domains = domains or self.domains
        total = len(target_domains)

        for i, domain_info in enumerate(target_domains):
            domain = domain_info["domain"]
            self.current_domain = domain
            self.progress = (i / total) * 100

            if progress_callback:
                progress_callback(self.progress, domain)

            try:
                result = self.scan_single(domain_info)
                self.results.append(result)
            except Exception as e:
                self.errors.append(f"{domain}: {str(e)}")

            # Small delay to be respectful
            time.sleep(0.2)

        self.scan_end = datetime.now(timezone.utc)
        self.is_scanning = False
        self.progress = 100.0

        if progress_callback:
            progress_callback(100.0, "Scan complete")

        return self.results

    def scan_single(self, domain_info: Dict[str, str]) -> Dict[str, Any]:
        """
        Run all scan modules against a single domain and produce a unified result.
        """
        domain = domain_info["domain"]
        now = datetime.now(timezone.utc)

        # Initialize result structure
        result = {
            "domain": domain,
            "name": domain_info.get("name", domain),
            "ministry": domain_info.get("ministry", "Unknown"),
            "category": domain_info.get("category", "governance"),
            "ip": None,
            "location": assign_location(domain),
            "scan_time": now.isoformat(),
            "dns": {},
            "ssl": {},
            "headers": {},
            "server": {},
            "ports": [],
            "findings": [],
            "risk_score": 0,
            "risk_level": RiskLevel.INFO.value,
        }

        # ── DNS Resolution ────────────────────────────────────────────────
        dns_result = resolve_domain(domain)
        result["dns"] = dns_result
        if dns_result.get("ip_addresses"):
            result["ip"] = dns_result["ip_addresses"][0]

        if not dns_result.get("resolved"):
            result["findings"].append("Domain does not resolve — may be decommissioned")
            result["risk_score"] = 10
            result["risk_level"] = RiskLevel.INFO.value
            return result

        # ── SSL Check ─────────────────────────────────────────────────────
        ssl_result = check_ssl(domain)
        ssl_grade = get_ssl_grade(ssl_result)
        result["ssl"] = {
            "status": ssl_result.get("status", "unknown"),
            "expiry": ssl_result.get("expiry"),
            "days_remaining": ssl_result.get("days_remaining"),
            "issuer": ssl_result.get("issuer"),
            "protocol": ssl_result.get("protocol"),
            "self_signed": ssl_result.get("self_signed", False),
            "grade": ssl_grade,
        }

        # SSL findings
        if ssl_result["status"] == "expired":
            result["findings"].append(f"SSL certificate EXPIRED ({abs(ssl_result.get('days_remaining', 0))} days ago)")
        elif ssl_result["status"] == "expiring":
            result["findings"].append(f"SSL certificate expiring in {ssl_result.get('days_remaining', '?')} days")
        elif ssl_result["status"] == "missing":
            result["findings"].append("No SSL/TLS certificate — site not secured with HTTPS")
        if ssl_result.get("self_signed"):
            result["findings"].append("Self-signed SSL certificate detected")

        # ── HTTP Headers ──────────────────────────────────────────────────
        header_result = analyze_headers(domain)
        server_check = check_server_version(header_result.get("server"))

        result["headers"] = {
            "reachable": header_result.get("reachable", False),
            "status_code": header_result.get("status_code"),
            "https_redirect": header_result.get("https_redirect", False),
            "missing_count": header_result.get("missing_count", 0),
            "missing_headers": header_result.get("missing_headers", []),
            "total": len(header_result.get("security_headers", {})),
            "score": header_result.get("header_score", 0),
            "technology": header_result.get("technology", []),
            "interesting": header_result.get("interesting_headers", {}),
        }

        result["server"] = {
            "banner": header_result.get("server"),
            "technology": server_check.get("banner", ""),
            "version": "",
            "status": server_check.get("status", "unknown"),
            "eol": server_check.get("eol", False),
            "details": server_check.get("details", ""),
        }

        # Parse technology/version from banner
        banner = header_result.get("server") or ""
        if "/" in banner:
            parts = banner.split("/", 1)
            result["server"]["technology"] = parts[0]
            result["server"]["version"] = parts[1].split(" ")[0] if len(parts) > 1 else ""

        # Header findings
        missing = header_result.get("missing_count", 0)
        if missing >= 5:
            result["findings"].append(f"Missing {missing}/7 critical security headers")
        elif missing >= 3:
            result["findings"].append(f"Missing {missing}/7 security headers")

        if not header_result.get("https_redirect") and header_result.get("reachable"):
            result["findings"].append("HTTP does not redirect to HTTPS")

        if server_check.get("eol"):
            result["findings"].append(f"End-of-life server: {banner}")
        elif server_check.get("status") == "outdated":
            result["findings"].append(f"Outdated server version: {banner}")

        # ── Shodan Integration (if available) ─────────────────────────────
        if self.shodan.available and result["ip"]:
            shodan_data = self.shodan.lookup_host(result["ip"])
            if "error" not in shodan_data:
                # Extract open ports from Shodan
                shodan_ports = shodan_data.get("ports", [])
                for port in shodan_ports:
                    port_type = classify_port(port)
                    port_info = {
                        "port": port,
                        "service": port_name(port),
                        "type": port_type,
                    }
                    # Avoid duplicates
                    existing_ports = {p["port"] for p in result["ports"]}
                    if port not in existing_ports:
                        result["ports"].append(port_info)

                    if port_type == "database":
                        result["findings"].append(
                            f"Exposed database port: {port} ({port_name(port)})"
                        )
                    elif port_type == "dangerous":
                        result["findings"].append(
                            f"Dangerous service exposed: {port} ({port_name(port)})"
                        )

                # CVEs from Shodan
                for vuln in shodan_data.get("vulns", []):
                    result["findings"].append(f"Known vulnerability: {vuln}")

        # Add standard ports if not already present
        existing_ports = {p["port"] for p in result["ports"]}
        for port in [80, 443]:
            if port not in existing_ports:
                result["ports"].append({
                    "port": port,
                    "service": port_name(port),
                    "type": "standard",
                })

        # ── Calculate Risk Score ──────────────────────────────────────────
        result["risk_score"] = self._calculate_risk_score(result)
        result["risk_level"] = classify_risk(result["risk_score"]).value

        return result

    def _calculate_risk_score(self, result: Dict[str, Any]) -> int:
        """Calculate a comprehensive risk score (0-100) for a scan result."""
        score = 0

        # SSL risk
        ssl_status = result.get("ssl", {}).get("status", "unknown")
        if ssl_status == "expired":
            score += 30
        elif ssl_status == "expiring":
            days = result.get("ssl", {}).get("days_remaining", 999)
            if days <= 7:
                score += 20
            elif days <= 30:
                score += 15
            elif days <= 90:
                score += 8
        elif ssl_status == "missing":
            score += 25
        if result.get("ssl", {}).get("self_signed"):
            score += 12

        # Port risk
        for port_info in result.get("ports", []):
            ptype = port_info.get("type", "standard")
            if ptype == "database":
                score += 20
            elif ptype == "dangerous":
                score += 15
            elif ptype == "admin":
                score += 12

        # Header risk
        missing_headers = result.get("headers", {}).get("missing_count", 0)
        score += missing_headers * 5

        # Server version risk
        server_status = result.get("server", {}).get("status", "unknown")
        if server_status == "eol":
            score += 30
        elif server_status == "outdated":
            score += 20

        # HTTPS redirect
        if not result.get("headers", {}).get("https_redirect", True):
            score += 8

        return min(score, 100)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the latest scan results."""
        if not self.results:
            return {"total": 0, "scanned": False}

        risk_scores = [r["risk_score"] for r in self.results]
        risk_levels = [r["risk_level"] for r in self.results]
        all_findings = []
        for r in self.results:
            all_findings.extend(r.get("findings", []))

        ssl_statuses = [r.get("ssl", {}).get("status", "unknown") for r in self.results]
        exposed_dbs = sum(
            1 for r in self.results
            for p in r.get("ports", [])
            if p.get("type") == "database"
        )

        return {
            "total": len(self.results),
            "scanned": True,
            "scan_duration": (
                (self.scan_end - self.scan_start).total_seconds()
                if self.scan_start and self.scan_end else 0
            ),
            "avg_risk": round(sum(risk_scores) / len(risk_scores), 1),
            "max_risk": max(risk_scores),
            "min_risk": min(risk_scores),
            "critical_count": risk_levels.count(RiskLevel.CRITICAL.value),
            "high_count": risk_levels.count(RiskLevel.HIGH.value),
            "medium_count": risk_levels.count(RiskLevel.MEDIUM.value),
            "low_count": risk_levels.count(RiskLevel.LOW.value),
            "info_count": risk_levels.count(RiskLevel.INFO.value),
            "total_findings": len(all_findings),
            "ssl_expired": ssl_statuses.count("expired"),
            "ssl_expiring": ssl_statuses.count("expiring"),
            "ssl_missing": ssl_statuses.count("missing"),
            "ssl_valid": ssl_statuses.count("valid"),
            "exposed_databases": exposed_dbs,
            "errors": len(self.errors),
        }
