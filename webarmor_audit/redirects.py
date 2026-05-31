"""
HTTP Redirect Chain auditor for WebArmor-Audit.
"""

from typing import List, Tuple
from urllib.parse import urlparse
import requests

from webarmor_audit.models import RedirectHop


def audit_redirect_chain(response: requests.Response) -> Tuple[List[RedirectHop], List[str]]:
    """
    Analyse the redirection history of an HTTP request.
    
    Checks for:
      - HTTPS to HTTP downgrades (very critical).
      - Cross-domain redirections that might leak headers or session data.
    """
    hops: List[RedirectHop] = []
    warnings: List[str] = []
    
    # Combine history (redirects) and the final response
    chain = list(response.history) + [response]
    
    # If there are no redirects, return empty lists
    if len(chain) <= 1:
        return [], []
        
    for resp in chain:
        url = resp.url
        status_code = resp.status_code
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        
        hops.append(
            RedirectHop(
                url=url,
                status_code=status_code,
                is_https=is_https,
                headers=dict(resp.headers)
            )
        )
        
    # Security checks on the redirect chain
    has_seen_https = False
    for hop in hops:
        if hop.is_https:
            has_seen_https = True
        elif has_seen_https and not hop.is_https:
            warnings.append(
                f"Downgrade Redirect: Secure HTTPS connection was downgraded to insecure "
                f"HTTP protocol at target '{hop.url}'."
            )
            
    # Cross-domain check
    if hops:
        first_host = urlparse(hops[0].url).hostname
        if first_host:
            first_parts = first_host.split(".")
            first_root = ".".join(first_parts[-2:]) if len(first_parts) >= 2 else first_host
            
            for hop in hops[1:]:
                curr_host = urlparse(hop.url).hostname
                if curr_host:
                    curr_parts = curr_host.split(".")
                    curr_root = ".".join(curr_parts[-2:]) if len(curr_parts) >= 2 else curr_host
                    
                    if first_root != curr_root:
                        warnings.append(
                            f"Cross-Domain Redirect: Redirected to a third-party host "
                            f"'{curr_host}' from '{first_host}'. This risks leaking session headers."
                        )
                        
    return hops, warnings
