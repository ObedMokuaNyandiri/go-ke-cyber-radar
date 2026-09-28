"""
.GO.KE Cyber-Surface Radar — Vulnerability Correlator
=======================================================
Maps detected software versions and configurations to known
CVEs and vulnerability patterns.
"""

from typing import Any, Dict, List, Optional

from utils.helpers import load_vulns
from config import RiskLevel


class VulnCorrelator:
    """Correlates scan results with known vulnerability data."""

    def __init__(self):
        vuln_data = load_vulns()
        self.server_vulns = vuln_data.get("server_vulns", {})
        self.port_vulns = vuln_data.get("port_vulns", {})

    def correlate(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find potential vulnerabilities for a scan result based on
        detected software versions and exposed services.

        Returns a list of potential vulnerability matches.
        """
        correlations = []

        # ── Server Banner Correlation ─────────────────────────────────────
        server_banner = scan_result.get("server", {}).get("banner", "")
        if server_banner:
            correlations.extend(self._match_server(server_banner, scan_result))

        # ── Technology Stack Correlation ──────────────────────────────────
        for tech in scan_result.get("headers", {}).get("technology", []):
            tech_name = tech.get("name", "")
            if tech_name:
                correlations.extend(self._match_server(tech_name, scan_result))

        # Interesting headers (X-Powered-By, etc.)
        for header_key, header_val in scan_result.get("headers", {}).get("interesting", {}).items():
            correlations.extend(self._match_server(header_val, scan_result))

        # ── Port-Based Correlation ────────────────────────────────────────
        for port_info in scan_result.get("ports", []):
            port = str(port_info.get("port", ""))
            if port in self.port_vulns:
                vuln_info = self.port_vulns[port]
                correlations.append({
                    "domain": scan_result.get("domain", "unknown"),
                    "type": "port_exposure",
                    "port": int(port),
                    "service": port_info.get("service", "unknown"),
                    "risk": vuln_info.get("risk", "MEDIUM"),
                    "title": vuln_info.get("title", f"Port {port} exposed"),
                    "cve": None,
                    "cvss": None,
                    "source": "port_analysis",
                })

        # Deduplicate
        seen = set()
        unique = []
        for c in correlations:
            key = f"{c.get('domain')}:{c.get('cve', '')}:{c.get('port', '')}:{c.get('title', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(c)

        return unique

    def _match_server(self, banner: str, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match a server/technology banner against known CVEs."""
        matches = []
        banner_lower = banner.lower()

        for pattern, cves in self.server_vulns.items():
            if pattern.lower() in banner_lower:
                for cve_info in cves:
                    matches.append({
                        "domain": scan_result.get("domain", "unknown"),
                        "type": "software_version",
                        "banner": banner,
                        "pattern_matched": pattern,
                        "cve": cve_info.get("cve", ""),
                        "severity": cve_info.get("severity", "MEDIUM"),
                        "risk": cve_info.get("severity", "MEDIUM"),
                        "title": cve_info.get("title", ""),
                        "cvss": cve_info.get("cvss"),
                        "source": "version_correlation",
                    })

        return matches

    def correlate_all(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run vulnerability correlation across all scan results.

        Returns summary with all correlations grouped by domain and severity.
        """
        all_correlations = []
        by_domain = {}
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for result in scan_results:
            domain = result.get("domain", "unknown")
            domain_vulns = self.correlate(result)
            all_correlations.extend(domain_vulns)
            by_domain[domain] = domain_vulns

            for v in domain_vulns:
                severity = v.get("severity", v.get("risk", "MEDIUM"))
                if severity in by_severity:
                    by_severity[severity] += 1

        # Get unique CVEs
        unique_cves = set()
        for c in all_correlations:
            if c.get("cve"):
                unique_cves.add(c["cve"])

        return {
            "total": len(all_correlations),
            "unique_cves": len(unique_cves),
            "cve_list": sorted(unique_cves),
            "by_domain": by_domain,
            "by_severity": by_severity,
            "all": all_correlations,
        }
