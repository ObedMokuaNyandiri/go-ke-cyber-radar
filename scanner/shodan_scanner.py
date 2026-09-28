"""
.GO.KE Cyber-Surface Radar — Shodan Scanner
=============================================
Integrates with the Shodan API to query indexed information about
.go.ke infrastructure. Uses only Shodan's passive index — no active scanning.
"""

from typing import Any, Dict, List, Optional

from config import SHODAN_API_KEY, KNOWN_PORTS
from utils.cache_manager import cache

# Try to import shodan; fall back gracefully
try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False


class ShodanScanner:
    """Wrapper around the Shodan API for .go.ke reconnaissance."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or SHODAN_API_KEY
        self.api = None
        self.available = False

        if HAS_SHODAN and self.api_key:
            try:
                self.api = shodan.Shodan(self.api_key)
                self.available = True
            except Exception:
                self.available = False

    def is_available(self) -> bool:
        """Check if the Shodan API is configured and accessible."""
        if not self.available:
            return False
        try:
            self.api.info()
            return True
        except Exception:
            return False

    def get_api_info(self) -> Dict[str, Any]:
        """Get Shodan API account info (credits, etc.)."""
        if not self.available:
            return {"error": "Shodan API not configured"}
        try:
            info = self.api.info()
            return {
                "scan_credits": info.get("scan_credits", 0),
                "query_credits": info.get("query_credits", 0),
                "plan": info.get("plan", "unknown"),
            }
        except Exception as e:
            return {"error": str(e)}

    def search_domain(self, domain: str = "go.ke", max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search Shodan for hosts under a domain.

        Args:
            domain: The domain to search for (default: go.ke)
            max_results: Maximum number of results to return

        Returns:
            List of host information dicts
        """
        cache_key = f"shodan:search:{domain}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        if not self.available:
            return []

        results = []
        try:
            query = f"hostname:.{domain}"
            search_results = self.api.search(query, limit=max_results)

            for match in search_results.get("matches", []):
                host_info = {
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "transport": match.get("transport", "tcp"),
                    "hostnames": match.get("hostnames", []),
                    "domains": match.get("domains", []),
                    "org": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "os": match.get("os"),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "banner": match.get("data", "")[:500],  # Truncate long banners
                    "location": {
                        "country": match.get("location", {}).get("country_name", ""),
                        "city": match.get("location", {}).get("city", ""),
                        "lat": match.get("location", {}).get("latitude"),
                        "lon": match.get("location", {}).get("longitude"),
                    },
                    "ssl": None,
                    "vulns": match.get("vulns", []),
                    "timestamp": match.get("timestamp", ""),
                }

                # Extract SSL info if present
                ssl_data = match.get("ssl", {})
                if ssl_data:
                    host_info["ssl"] = {
                        "cipher": ssl_data.get("cipher", {}),
                        "version": ssl_data.get("versions", []),
                        "cert": {
                            "subject": ssl_data.get("cert", {}).get("subject", {}),
                            "issuer": ssl_data.get("cert", {}).get("issuer", {}),
                            "expires": ssl_data.get("cert", {}).get("expires", ""),
                        },
                    }

                results.append(host_info)

            # Cache for 1 hour
            cache.set(cache_key, results, ttl=3600)

        except shodan.APIError as e:
            if "access denied" in str(e).lower():
                pass  # Free API limitations
            # Return empty results on API error
        except Exception:
            pass

        return results

    def lookup_host(self, ip: str) -> Dict[str, Any]:
        """
        Look up detailed information about a specific IP address.
        """
        cache_key = f"shodan:host:{ip}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        if not self.available:
            return {"error": "Shodan API not configured"}

        try:
            host = self.api.host(ip)
            result = {
                "ip": host.get("ip_str", ip),
                "hostnames": host.get("hostnames", []),
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "vulns": host.get("vulns", []),
                "location": {
                    "country": host.get("country_name", ""),
                    "city": host.get("city", ""),
                    "lat": host.get("latitude"),
                    "lon": host.get("longitude"),
                },
                "services": [],
                "last_update": host.get("last_update", ""),
            }

            # Parse services from data
            for service in host.get("data", []):
                svc = {
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "banner": service.get("data", "")[:300],
                    "service_name": KNOWN_PORTS.get(service.get("port", 0), "unknown"),
                }
                result["services"].append(svc)

            cache.set(cache_key, result, ttl=3600)
            return result

        except shodan.APIError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Lookup failed: {str(e)}"}

    def count_results(self, domain: str = "go.ke") -> int:
        """Get the total count of Shodan results for a domain."""
        if not self.available:
            return 0
        try:
            result = self.api.count(f"hostname:.{domain}")
            return result.get("total", 0)
        except Exception:
            return 0
