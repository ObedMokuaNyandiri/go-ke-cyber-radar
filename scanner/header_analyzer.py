"""
.GO.KE Cyber-Surface Radar — HTTP Header Analyzer
====================================================
Analyzes HTTP response headers to detect server technologies,
missing security headers, and misconfigurations.
Passive reconnaissance only — standard HTTP GET requests.
"""

import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from config import (
    HTTP_CHECK_TIMEOUT, SECURITY_HEADERS, HEADER_DESCRIPTIONS,
    OUTDATED_SERVERS,
)
from utils.cache_manager import cache


def analyze_headers(domain: str) -> Dict[str, Any]:
    """
    Analyze HTTP response headers for a domain.

    Returns a dict with:
        - reachable: bool — whether the domain responded
        - https_redirect: bool — whether HTTP redirects to HTTPS
        - server: server header value
        - technology: detected web technology stack
        - security_headers: dict of header → present/absent
        - missing_headers: list of absent security headers
        - cookies: list of cookie names and their flags
        - interesting_headers: any unusual or revealing headers
    """
    cache_key = f"headers:{domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    result = {
        "domain": domain,
        "reachable": False,
        "status_code": None,
        "https_redirect": False,
        "server": None,
        "technology": [],
        "security_headers": {},
        "missing_headers": [],
        "missing_count": 0,
        "header_score": 0,
        "cookies": [],
        "interesting_headers": {},
        "error": None,
    }

    # Try HTTPS first, then HTTP
    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                timeout=HTTP_CHECK_TIMEOUT,
                allow_redirects=True,
                verify=False,  # Don't fail on bad certs
                headers={"User-Agent": "CyberRadar/1.0 (Security Research)"},
            )

            result["reachable"] = True
            result["status_code"] = resp.status_code
            headers = resp.headers

            # Check HTTPS redirect
            if url.startswith("http://"):
                final_url = resp.url
                result["https_redirect"] = final_url.startswith("https://")

            # Server identification
            result["server"] = headers.get("Server")

            # Technology detection from headers
            techs = _detect_technologies(headers)
            result["technology"] = techs

            # Security headers check
            for header in SECURITY_HEADERS:
                present = header.lower() in {h.lower() for h in headers.keys()}
                result["security_headers"][header] = {
                    "present": present,
                    "value": headers.get(header),
                    "description": HEADER_DESCRIPTIONS.get(header, ""),
                }
                if not present:
                    result["missing_headers"].append(header)

            result["missing_count"] = len(result["missing_headers"])
            total_headers = len(SECURITY_HEADERS)
            present_count = total_headers - result["missing_count"]
            result["header_score"] = round((present_count / total_headers) * 100)

            # Cookie analysis
            if "Set-Cookie" in headers:
                cookies = resp.cookies
                for cookie in cookies:
                    cookie_info = {
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "httponly": bool(cookie._rest.get("HttpOnly", False)),
                        "samesite": cookie._rest.get("SameSite", "Not Set"),
                        "domain": cookie.domain,
                    }
                    result["cookies"].append(cookie_info)

            # Interesting / revealing headers
            interesting_keys = [
                "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                "X-Generator", "X-Drupal-Cache", "X-Varnish",
                "X-Cache", "X-CDN", "Via", "X-Runtime",
                "X-Request-Id", "X-Debug", "X-WordPress",
            ]
            for key in interesting_keys:
                val = headers.get(key)
                if val:
                    result["interesting_headers"][key] = val

            break  # Success, don't try next URL

        except requests.exceptions.SSLError:
            if url.startswith("https://"):
                continue  # Try HTTP fallback
            result["error"] = "SSL connection error"
        except requests.exceptions.ConnectionError:
            if url.startswith("https://"):
                continue  # Try HTTP fallback
            result["error"] = "Connection refused"
        except requests.exceptions.Timeout:
            result["error"] = "Connection timed out"
        except requests.exceptions.RequestException as e:
            result["error"] = f"Request error: {str(e)}"

    # Cache result
    ttl = 3600 if result["reachable"] else 300
    cache.set(cache_key, result, ttl=ttl)

    return result


def _detect_technologies(headers: dict) -> List[Dict[str, str]]:
    """Detect web technologies from response headers."""
    techs = []
    header_map = {k.lower(): v for k, v in headers.items()}

    # Server software
    server = header_map.get("server", "")
    if server:
        techs.append({"name": server.split("(")[0].strip(), "category": "server", "raw": server})

    # PHP
    powered_by = header_map.get("x-powered-by", "")
    if "php" in powered_by.lower():
        techs.append({"name": powered_by, "category": "language", "raw": powered_by})

    # ASP.NET
    aspnet = header_map.get("x-aspnet-version", "")
    if aspnet:
        techs.append({"name": f"ASP.NET {aspnet}", "category": "framework", "raw": aspnet})

    # WordPress
    if any(k in header_map for k in ["x-wordpress", "x-drupal-cache"]):
        cms = "WordPress" if "x-wordpress" in header_map else "Drupal"
        techs.append({"name": cms, "category": "cms", "raw": header_map.get(f"x-{cms.lower()}", "")})

    # CDN / Proxy
    via = header_map.get("via", "")
    if via:
        techs.append({"name": f"Proxy: {via}", "category": "proxy", "raw": via})

    x_cache = header_map.get("x-cache", "")
    if x_cache:
        techs.append({"name": f"Cache: {x_cache}", "category": "cache", "raw": x_cache})

    return techs


def check_server_version(server_banner: Optional[str]) -> Dict[str, Any]:
    """
    Check if a server version is outdated or end-of-life.
    """
    if not server_banner:
        return {"status": "unknown", "details": "No server banner"}

    result = {
        "banner": server_banner,
        "status": "current",
        "eol": False,
        "details": "Server version appears current",
        "latest": None,
        "eol_date": None,
    }

    banner_lower = server_banner.lower()

    for pattern, info in OUTDATED_SERVERS.items():
        if pattern.lower() in banner_lower:
            result["status"] = info["status"]
            result["eol"] = info["status"] == "eol"
            result["latest"] = info.get("latest")
            result["eol_date"] = info.get("eol_date")

            if result["eol"]:
                result["details"] = f"END OF LIFE since {info.get('eol_date', 'unknown')} — no security patches"
            else:
                result["details"] = f"Outdated — latest version is {info.get('latest', 'unknown')}"
            break

    return result
