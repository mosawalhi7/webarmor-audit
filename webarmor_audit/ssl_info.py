"""
SSL/TLS certificate information retrieval for WebArmor-Audit.

Uses Python's built-in ``ssl`` and ``socket`` modules (no third-party
dependencies) to fetch and parse the peer certificate from a given
hostname.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from webarmor_audit.constants import DEFAULT_PORT, DEFAULT_TIMEOUT
from webarmor_audit.models import SSLInfo


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """
    Parse an OpenSSL-style date string into a timezone-aware datetime.

    Expected format: ``'Mon DD HH:MM:SS YYYY GMT'``
    """
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None


def _flatten_rdns(rdns: Any) -> str:
    """
    Flatten the nested tuple structure returned by ``ssl.getpeercert()``
    for *issuer* / *subject* into a human-readable string.

    Example input::

        ((('countryName', 'US'),), (('organizationName', 'DigiCert Inc'),), ...)

    Returns::

        "countryName=US, organizationName=DigiCert Inc, ..."
    """
    if not rdns:
        return "N/A"
    parts: list[str] = []
    for rdn in rdns:
        for attr_name, attr_value in rdn:
            parts.append(f"{attr_name}={attr_value}")
    return ", ".join(parts)


def _test_tls_version(hostname: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """Attempt a handshake forcing a specific TLS version."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except (ssl.SSLError, socket.error, ValueError, AttributeError):
        return False


def _test_cipher_group(hostname: str, port: int, cipher_query: str, timeout: float) -> bool:
    """Attempt a handshake forcing a specific cipher suite group."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Allow older TLS protocols since weak ciphers are often negotiated only on <= TLS 1.2
        if hasattr(ssl, "TLSVersion"):
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
        context.set_ciphers(cipher_query)
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except (ssl.SSLError, socket.error, ValueError, AttributeError):
        return False


def _perform_active_ssl_scan(
    hostname: str,
    port: int,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Perform active testing of TLS versions and weak cipher suites.
    Uses a shorter timeout (max 3 seconds) for individual attempts to keep it fast.
    """
    test_timeout = min(3.0, float(timeout))

    supported_tls = []
    rejected_tls = []
    
    # 1. Test TLS Versions
    if hasattr(ssl, "TLSVersion"):
        for attr, name in [
            ("TLSv1_3", "TLSv1.3"),
            ("TLSv1_2", "TLSv1.2"),
            ("TLSv1_1", "TLSv1.1"),
            ("TLSv1", "TLSv1.0"),
            ("SSLv3", "SSLv3"),
        ]:
            if hasattr(ssl.TLSVersion, attr):
                ver_enum = getattr(ssl.TLSVersion, attr)
                if _test_tls_version(hostname, port, ver_enum, test_timeout):
                    supported_tls.append(name)
                else:
                    try:
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx.minimum_version = ver_enum
                        ctx.maximum_version = ver_enum
                        rejected_tls.append(name)
                    except (ValueError, AttributeError):
                        pass

    # 2. Test Weak Cipher Suites
    supported_weak = []
    weak_groups = {
        "RC4": "RC4",
        "3DES": "3DES",
        "aNULL": "aNULL",
        "eNULL": "eNULL",
        "EXPORT": "EXPORT",
    }
    
    for cipher_name, cipher_query in weak_groups.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.set_ciphers(cipher_query)
            if _test_cipher_group(hostname, port, cipher_query, test_timeout):
                supported_weak.append(cipher_name)
        except (ValueError, ssl.SSLError):
            pass

    has_tls10_or_below = any(v in supported_tls for v in ["TLSv1.0", "TLSv1.1", "SSLv3"])
    has_weak_ciphers = len(supported_weak) > 0

    return {
        "supported_tls_versions": supported_tls,
        "rejected_tls_versions": rejected_tls,
        "supported_weak_ciphers": supported_weak,
        "has_tls10_or_below": has_tls10_or_below,
        "has_weak_ciphers": has_weak_ciphers,
    }


def fetch_ssl_info(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> SSLInfo:
    """
    Connect to *url*'s host on port 443 and retrieve SSL certificate
    details.

    Returns a populated :class:`SSLInfo` dataclass.  On failure the
    ``error`` field describes what went wrong, and ``is_valid`` is
    ``False``.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname: Optional[str] = parsed.hostname
    port: int = parsed.port or DEFAULT_PORT

    if not hostname:
        return SSLInfo(error="Could not extract hostname from URL")

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert: Dict[str, Any] = tls_sock.getpeercert()  # type: ignore[assignment]
    except ssl.SSLCertVerificationError as exc:
        return SSLInfo(error=f"Certificate verification failed: {exc}")
    except ssl.SSLError as exc:
        return SSLInfo(error=f"SSL error: {exc}")
    except socket.timeout:
        return SSLInfo(error=f"Connection timed out after {timeout}s")
    except OSError as exc:
        return SSLInfo(error=f"Socket error: {exc}")

    if not cert:
        return SSLInfo(error="Peer returned an empty certificate")

    # Parse certificate fields ------------------------------------------------
    issuer_str = _flatten_rdns(cert.get("issuer"))
    subject_str = _flatten_rdns(cert.get("subject"))
    serial = cert.get("serialNumber", "N/A")
    version = cert.get("version", 0)

    not_before = _parse_cert_date(cert.get("notBefore", ""))
    not_after = _parse_cert_date(cert.get("notAfter", ""))

    days_remaining = -1
    if not_after:
        delta = not_after - datetime.now(tz=timezone.utc)
        days_remaining = delta.days

    # Perform active protocols and ciphers scanning
    active_results = _perform_active_ssl_scan(hostname, port, timeout)

    return SSLInfo(
        issuer=issuer_str,
        subject=subject_str,
        serial_number=str(serial),
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        version=version,
        is_valid=days_remaining > 0,
        supported_tls_versions=active_results["supported_tls_versions"],
        rejected_tls_versions=active_results["rejected_tls_versions"],
        supported_weak_ciphers=active_results["supported_weak_ciphers"],
        has_tls10_or_below=active_results["has_tls10_or_below"],
        has_weak_ciphers=active_results["has_weak_ciphers"],
    )
