"""
HTTP/2 and HTTP/3 protocol support analyzer for WebArmor-Audit.
"""

import socket
import ssl
from typing import Dict, List
from urllib.parse import urlparse


def check_http2(url: str, timeout: int = 5) -> bool:
    """
    Check if the target server supports HTTP/2 using TLS ALPN negotiation.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
        
    hostname = parsed.hostname
    if not hostname:
        return False
        
    port = parsed.port or 443
    
    # Configure SSL context to request h2 ALPN protocol
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated = ssock.selected_alpn_protocol()
                return negotiated == "h2"
    except Exception:
        return False


def check_http3_passive(response_headers: Dict[str, str]) -> bool:
    """
    Check if the target server advertises HTTP/3 support via Alt-Svc headers.
    """
    # Look for alt-svc header (case-insensitive)
    norm_headers = {k.lower(): v for k, v in response_headers.items()}
    alt_svc = norm_headers.get("alt-svc", "")
    
    # Check if 'h3' or 'h3-xx' is present in the Alt-Svc header value
    return "h3" in alt_svc.lower()


def audit_protocols(url: str, response_headers: Dict[str, str], timeout: int = 5) -> List[str]:
    """
    Audit supported HTTP protocols.
    
    Returns a list of supported protocol identifiers (e.g. ['HTTP/1.1', 'HTTP/2']).
    """
    supported = ["HTTP/1.1"]  # HTTP/1.1 is assumed as we successfully fetched headers
    
    if check_http2(url, timeout=timeout):
        supported.append("HTTP/2")
        
    if check_http3_passive(response_headers):
        supported.append("HTTP/3")
        
    return supported
