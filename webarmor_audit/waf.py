"""
Web Application Firewall (WAF) detector module for WebArmor-Audit.
Identifies firewalls by analyzing response headers and cookie signatures.
"""

from __future__ import annotations

from typing import Dict, List
from webarmor_audit.models import WAFDetails


def detect_waf(headers: Dict[str, str], cookies: List[str]) -> WAFDetails:
    """
    Examine response headers and set-cookie values to finger-print WAF existence.
    """
    # Normalise headers keys to lower-case
    norm_headers = {k.lower(): v.lower() for k, v in headers.items()}
    joined_cookies = "; ".join(cookies).lower()
    
    # 1. Cloudflare Check
    if "cf-ray" in norm_headers or "__cfduid" in joined_cookies or "cf-cache-status" in norm_headers:
        return WAFDetails(
            detected=True,
            waf_name="Cloudflare",
            reason="Presence of Cloudflare headers (CF-Ray / CF-Cache-Status) or tracking cookies.",
            signature_type="Header/Cookie"
        )
    if norm_headers.get("server") == "cloudflare":
        return WAFDetails(
            detected=True,
            waf_name="Cloudflare",
            reason="Server banner indicates 'cloudflare'.",
            signature_type="Header"
        )
        
    # 2. AWS WAF Check
    if "awselb" in joined_cookies or "awsalb" in joined_cookies or "awsalbtg" in joined_cookies or "awsalbcors" in joined_cookies:
        return WAFDetails(
            detected=True,
            waf_name="AWS WAF / Elastic Load Balancer",
            reason="Presence of AWS Elastic Load Balancing tracking cookies.",
            signature_type="Cookie"
        )
        
    # 3. Akamai Check
    if "x-akamai-transformed" in norm_headers or "akamai-origin-hop" in norm_headers or "x-true-client-ip" in norm_headers:
        return WAFDetails(
            detected=True,
            waf_name="Akamai WAF",
            reason="Akamai header routing flags detected.",
            signature_type="Header"
        )
        
    # 4. Imperva / Incapsula Check
    if "visid_incap" in joined_cookies or "incap_ses" in joined_cookies or "x-cdn" in norm_headers and "incapsula" in norm_headers["x-cdn"]:
        return WAFDetails(
            detected=True,
            waf_name="Imperva Incapsula WAF",
            reason="Imperva/Incapsula session verification cookies or custom X-CDN routing headers.",
            signature_type="Cookie/Header"
        )
        
    # 5. ModSecurity WAF
    if "mod_security" in norm_headers.get("server", "") or "modsecurity" in norm_headers.get("server", ""):
        return WAFDetails(
            detected=True,
            waf_name="ModSecurity WAF",
            reason="Server header exposes ModSecurity engine.",
            signature_type="Header"
        )
        
    # 6. FortiWeb WAF
    if "fortiwafsid" in joined_cookies:
        return WAFDetails(
            detected=True,
            waf_name="Fortinet FortiWeb WAF",
            reason="FortiWeb session cookie detected.",
            signature_type="Cookie"
        )

    # 7. F5 BIG-IP ASM
    if "ts" in joined_cookies: # TSXXXX cookies
        # F5 typically sets cookie prefix TS
        for c in cookies:
            parts = c.split("=")
            if parts and parts[0].strip().upper().startswith("TS") and len(parts[0].strip()) == 8:
                return WAFDetails(
                    detected=True,
                    waf_name="F5 BIG-IP ASM WAF",
                    reason="Presence of F5 Big-IP Application Security Manager cookies.",
                    signature_type="Cookie"
                )

    return WAFDetails(
        detected=False,
        waf_name="None",
        reason="No known WAF signature was identified in HTTP response headers or cookies.",
        signature_type="None"
    )
