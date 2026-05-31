"""
security.txt checker for WebArmor-Audit.
"""

from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
import requests
from typing import List, Optional

from webarmor_audit.constants import DEFAULT_TIMEOUT, USER_AGENT
from webarmor_audit.models import SecurityTxtFinding


def audit_security_txt(
    base_url: str,
    timeout: int = 5,
    verify_ssl: bool = True
) -> SecurityTxtFinding:
    """
    Check for the presence and validity of the security.txt file (RFC 9116).
    
    Checks both:
      - /.well-known/security.txt (Preferred)
      - /security.txt (Legacy fallback)
    """
    parsed = urlparse(base_url)
    origin_url = f"{parsed.scheme}://{parsed.netloc}"
    
    paths_to_check = [
        urljoin(origin_url, "/.well-known/security.txt"),
        urljoin(origin_url, "/security.txt")
    ]
    
    headers_to_send = {
        "User-Agent": USER_AGENT,
    }
    
    last_status = 0
    checked_url = paths_to_check[0]
    
    for url in paths_to_check:
        checked_url = url
        try:
            response = requests.get(
                url,
                headers=headers_to_send,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True
            )
            last_status = response.status_code
            if response.status_code == 200:
                # Successfully retrieved
                content = response.text
                return _parse_security_txt(content, url, last_status)
        except requests.RequestException:
            last_status = 0
            continue
            
    # If not found or failed
    issues = ["No security.txt file discovered at standard locations."]
    return SecurityTxtFinding(
        present=False,
        url_checked=origin_url,
        status_code=last_status,
        issues=issues,
        recommendation="Create a security.txt file under /.well-known/security.txt containing Contact and Expires fields."
    )


def _parse_security_txt(content: str, url: str, status_code: int) -> SecurityTxtFinding:
    """Parse security.txt text and evaluate standard compliance."""
    has_contact = False
    has_expires = False
    is_expired = False
    expires_date_str: Optional[str] = None
    issues: List[str] = []
    
    # Process lines
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
            
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()
            
            if key == "contact":
                has_contact = True
            elif key == "expires":
                has_expires = True
                expires_date_str = val
                # Parse expiration date
                is_expired = _check_if_expired(val)
                
    if not has_contact:
        issues.append("Missing mandatory 'Contact' field in security.txt.")
    if not has_expires:
        issues.append("Missing mandatory 'Expires' field in security.txt.")
    elif is_expired:
        issues.append(f"The security.txt file has expired (Expiration: {expires_date_str}).")
        
    recommendation = ""
    if issues:
        recommendation = "Update security.txt and ensure it has a valid 'Contact' email/link and a future 'Expires' timestamp."
        
    # Check if we retrieved from /security.txt instead of /.well-known/security.txt
    if "/.well-known/" not in url:
        issues.append("security.txt was found at the root, but it is recommended to place it under /.well-known/security.txt.")
        if not recommendation:
            recommendation = "Move security.txt to /.well-known/security.txt."
            
    return SecurityTxtFinding(
        present=True,
        url_checked=url,
        status_code=status_code,
        has_contact=has_contact,
        has_expires=has_expires,
        is_expired=is_expired,
        expires_date=expires_date_str,
        issues=issues,
        recommendation=recommendation
    )


def _check_if_expired(expires_str: str) -> bool:
    """Helper to check if expiration datetime string is in the past."""
    # Attempt to parse ISO format, e.g. "2026-12-31T23:59:59Z" or similar
    # Strip any comments if present
    if "#" in expires_str:
        expires_str = expires_str.split("#")[0].strip()
        
    # Common format replacements
    expires_str = expires_str.replace("Z", "+00:00")
    
    try:
        # standard ISO format parsing
        dt = datetime.fromisoformat(expires_str)
        # Convert to aware UTC datetime
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > dt
    except ValueError:
        # Fallback if format is not standard ISO, check basic string matches
        # or treat as not expired if we can't parse it
        return False
