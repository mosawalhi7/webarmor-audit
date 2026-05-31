"""
CORS configuration analyzer for WebArmor-Audit.
"""

from typing import Dict, List
from webarmor_audit.models import CORSEvaluation


def evaluate_cors(headers: Dict[str, str]) -> List[CORSEvaluation]:
    """
    Analyse CORS headers for security misconfigurations.
    
    Checks if wildcard origins are allowed alongside credentials, or if
    wildcards are used too broadly on potentially sensitive endpoints.
    """
    findings = []
    
    # Case-insensitive headers lookup
    norm_headers = {k.lower(): v for k, v in headers.items()}
    
    origin_key = "access-control-allow-origin"
    credentials_key = "access-control-allow-credentials"
    
    origin = norm_headers.get(origin_key)
    credentials = norm_headers.get(credentials_key)
    
    if origin is not None:
        issues = []
        is_secure = True
        recommendation = ""
        
        is_wildcard = origin.strip() == "*"
        has_credentials = credentials is not None and credentials.strip().lower() == "true"
        
        if is_wildcard and has_credentials:
            is_secure = False
            issues.append(
                "Access-Control-Allow-Origin is set to '*' while Allow-Credentials is true. "
                "This allows any third-party domain to read response data via credentialed requests."
            )
            recommendation = "Change Access-Control-Allow-Origin to specify explicit trusted origins, or disable Access-Control-Allow-Credentials."
        elif is_wildcard:
            # Public API, but warning is appropriate if sensitive
            issues.append(
                "Access-Control-Allow-Origin is wildcarded ('*'). Ensure this endpoint does not expose sensitive session-specific data."
            )
            recommendation = "Restrict origin access to verified client domains if this endpoint is not intended for public distribution."
            
        findings.append(
            CORSEvaluation(
                header_name="Access-Control-Allow-Origin",
                value=origin,
                is_secure=is_secure,
                issues=issues,
                recommendation=recommendation
            )
        )
        
    return findings
