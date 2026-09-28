"""
.GO.KE Cyber-Surface Radar — DNS Enumerator
=============================================
Performs passive DNS enumeration for .go.ke domains.
Resolves DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA) to map
the government's DNS infrastructure.
"""

import socket
from typing import Any, Dict, List, Optional

from utils.cache_manager import cache
from config import DNS_TIMEOUT

# Try to import dnspython; fall back gracefully if unavailable
try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def resolve_domain(domain: str) -> Dict[str, Any]:
    """
    Perform comprehensive DNS resolution for a domain.

    Returns a dict with:
        - resolved: bool — whether the domain resolves at all
        - ip_addresses: list of resolved IP addresses
        - records: dict of record types to their values
        - nameservers: list of authoritative nameservers
        - mail_servers: list of MX records
        - cname: CNAME target if applicable
        - txt_records: TXT record values
        - error: error message if resolution failed
    """
    # Check cache
    cache_key = f"dns:{domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    result = {
        "domain": domain,
        "resolved": False,
        "ip_addresses": [],
        "ipv6_addresses": [],
        "records": {},
        "nameservers": [],
        "mail_servers": [],
        "cname": None,
        "txt_records": [],
        "soa": None,
        "error": None,
    }

    if HAS_DNSPYTHON:
        result = _resolve_with_dnspython(domain, result)
    else:
        result = _resolve_with_socket(domain, result)

    # Cache result
    ttl = 3600 if result["resolved"] else 600
    cache.set(cache_key, result, ttl=ttl)

    return result


def _resolve_with_dnspython(domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Full DNS resolution using dnspython."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    # A records
    try:
        answers = resolver.resolve(domain, "A")
        result["ip_addresses"] = [str(rdata) for rdata in answers]
        result["records"]["A"] = result["ip_addresses"]
        result["resolved"] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # AAAA records (IPv6)
    try:
        answers = resolver.resolve(domain, "AAAA")
        result["ipv6_addresses"] = [str(rdata) for rdata in answers]
        result["records"]["AAAA"] = result["ipv6_addresses"]
        result["resolved"] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # CNAME records
    try:
        answers = resolver.resolve(domain, "CNAME")
        cnames = [str(rdata.target) for rdata in answers]
        if cnames:
            result["cname"] = cnames[0]
            result["records"]["CNAME"] = cnames
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = []
        for rdata in answers:
            mx_records.append({
                "priority": rdata.preference,
                "server": str(rdata.exchange),
            })
        result["mail_servers"] = sorted(mx_records, key=lambda x: x["priority"])
        result["records"]["MX"] = [f"{mx['priority']} {mx['server']}" for mx in result["mail_servers"]]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # NS records
    try:
        answers = resolver.resolve(domain, "NS")
        result["nameservers"] = [str(rdata) for rdata in answers]
        result["records"]["NS"] = result["nameservers"]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # TXT records (may contain SPF, DKIM, DMARC)
    try:
        answers = resolver.resolve(domain, "TXT")
        result["txt_records"] = [str(rdata).strip('"') for rdata in answers]
        result["records"]["TXT"] = result["txt_records"]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # SOA record
    try:
        answers = resolver.resolve(domain, "SOA")
        for rdata in answers:
            result["soa"] = {
                "mname": str(rdata.mname),
                "rname": str(rdata.rname),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum,
            }
            result["records"]["SOA"] = str(rdata)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    if not result["resolved"] and not result["ip_addresses"]:
        result["error"] = "Domain does not resolve"

    return result


def _resolve_with_socket(domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback DNS resolution using socket (limited to A records)."""
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        ip_list = list(set(addr[4][0] for addr in ips))
        result["ip_addresses"] = ip_list
        result["records"]["A"] = ip_list
        result["resolved"] = bool(ip_list)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result


def check_email_security(domain: str) -> Dict[str, Any]:
    """
    Check email security configuration (SPF, DKIM, DMARC) from DNS TXT records.
    """
    dns_result = resolve_domain(domain)
    email_security = {
        "spf": False,
        "spf_record": None,
        "dmarc": False,
        "dmarc_record": None,
        "dkim": False,
    }

    # Check SPF in TXT records
    for txt in dns_result.get("txt_records", []):
        if "v=spf1" in txt.lower():
            email_security["spf"] = True
            email_security["spf_record"] = txt

    # Check DMARC (separate _dmarc subdomain)
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=dmarc1" in txt.lower():
                    email_security["dmarc"] = True
                    email_security["dmarc_record"] = txt
        except Exception:
            pass

    return email_security
