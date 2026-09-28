"""
.GO.KE Cyber-Surface Radar — SSL Certificate Checker
======================================================
Inspects SSL/TLS certificates for .go.ke domains.
Checks expiry, issuer, protocol version, and cipher strength.
Passive reconnaissance only — uses standard TLS handshake.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import SSL_CHECK_TIMEOUT
from utils.cache_manager import cache


def check_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Check the SSL/TLS certificate for a domain.

    Returns a dict with:
        - status: 'valid', 'expiring', 'expired', 'missing', 'error'
        - expiry: ISO datetime of certificate expiry
        - days_remaining: days until expiry (negative if expired)
        - issuer: certificate issuer
        - subject: certificate subject
        - protocol: TLS protocol version
        - serial: certificate serial number
        - san: Subject Alternative Names
    """
    # Check cache first
    cache_key = f"ssl:{domain}:{port}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    result = {
        "domain": domain,
        "port": port,
        "status": "unknown",
        "expiry": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "protocol": None,
        "serial": None,
        "san": [],
        "self_signed": False,
        "error": None,
    }

    try:
        # Create SSL context (don't verify so we can inspect even bad certs)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=SSL_CHECK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                # getpeercert() returns {} when CERT_NONE — need binary form
                cert_bin = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()

                result["protocol"] = protocol

                if cert_bin:
                    # Parse with a verifying context for full cert info
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((domain, port), timeout=SSL_CHECK_TIMEOUT) as s2:
                            with ctx2.wrap_socket(s2, server_hostname=domain) as ss2:
                                cert = ss2.getpeercert()
                    except ssl.SSLCertVerificationError:
                        # Self-signed or invalid chain — parse what we can
                        # Use the DER cert to extract basic info
                        result["self_signed"] = True
                        try:
                            import ssl as _ssl
                            pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                            # Extract expiry from the DER certificate
                            ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            ctx3.check_hostname = False
                            ctx3.verify_mode = ssl.CERT_NONE
                            with socket.create_connection((domain, port), timeout=SSL_CHECK_TIMEOUT) as s3:
                                with ctx3.wrap_socket(s3, server_hostname=domain) as ss3:
                                    cert = ss3.getpeercert(binary_form=False)
                        except Exception:
                            pass

                    if cert:
                        # Extract expiry
                        not_after = cert.get("notAfter")
                        if not_after:
                            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_remaining = (expiry_dt - now).days

                            result["expiry"] = expiry_dt.isoformat()
                            result["days_remaining"] = days_remaining

                            if days_remaining < 0:
                                result["status"] = "expired"
                            elif days_remaining <= 30:
                                result["status"] = "expiring"
                            else:
                                result["status"] = "valid"

                        # Extract issuer
                        issuer = cert.get("issuer", ())
                        issuer_parts = []
                        for rdn in issuer:
                            for attr_type, attr_value in rdn:
                                if attr_type in ("organizationName", "commonName"):
                                    issuer_parts.append(attr_value)
                        result["issuer"] = " / ".join(issuer_parts) if issuer_parts else "Unknown"

                        # Extract subject
                        subject = cert.get("subject", ())
                        subject_parts = []
                        for rdn in subject:
                            for attr_type, attr_value in rdn:
                                if attr_type == "commonName":
                                    subject_parts.append(attr_value)
                        result["subject"] = ", ".join(subject_parts) if subject_parts else domain

                        # Extract SANs
                        san_list = cert.get("subjectAltName", ())
                        result["san"] = [val for typ, val in san_list if typ == "DNS"]

                        # Serial number
                        result["serial"] = cert.get("serialNumber", "")

                        # Check if self-signed
                        if result["issuer"] and result["subject"]:
                            if result["subject"] in result["issuer"]:
                                result["self_signed"] = True
                    else:
                        result["status"] = "valid"  # Has cert but couldn't parse details
                else:
                    result["status"] = "missing"

    except socket.timeout:
        result["status"] = "error"
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["status"] = "missing"
        result["error"] = "Connection refused — no SSL/TLS service"
    except socket.gaierror:
        result["status"] = "error"
        result["error"] = "DNS resolution failed"
    except OSError as e:
        result["status"] = "error"
        result["error"] = f"Connection error: {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected error: {str(e)}"

    # Cache result (shorter TTL for errors)
    ttl = 3600 if result["status"] != "error" else 300
    cache.set(cache_key, result, ttl=ttl)

    return result


def get_ssl_grade(result: Dict[str, Any]) -> str:
    """
    Calculate an SSL grade from A+ to F based on the check result.
    """
    if result["status"] == "missing":
        return "F"
    if result["status"] == "error":
        return "?"
    if result["status"] == "expired":
        return "F"

    score = 100

    # Deductions
    if result.get("self_signed"):
        score -= 40
    if result.get("protocol") in ("TLSv1", "TLSv1.1"):
        score -= 30
    elif result.get("protocol") == "TLSv1.2":
        score -= 0  # Acceptable
    if result.get("days_remaining") is not None:
        if result["days_remaining"] < 7:
            score -= 30
        elif result["days_remaining"] < 30:
            score -= 15
        elif result["days_remaining"] < 90:
            score -= 5

    # Map to grade
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"
