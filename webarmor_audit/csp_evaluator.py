"""
Content-Security-Policy (CSP) bypass evaluator for WebArmor-Audit.
"""

from typing import Dict, List, Optional


def evaluate_csp_bypass(csp_value: Optional[str]) -> List[str]:
    """
    Analyse Content-Security-Policy for common bypass configurations.
    
    Looks for wildcards, unsafe-inline/eval directives, trusted CDN bypasses
    (e.g., cdnjs, jsDelivr), and missing key directives like base-uri or object-src.
    """
    warnings: List[str] = []
    if not csp_value:
        return warnings

    # Parse directives into a dictionary
    directives: Dict[str, List[str]] = {}
    parts = csp_value.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        dir_name = tokens[0].lower()
        # Strip quotes and double quotes for clean matching
        dir_values = [t.strip().strip("'\"").lower() for t in tokens[1:]]
        directives[dir_name] = dir_values

    # Determine script-src fallback to default-src
    script_values = directives.get("script-src", directives.get("default-src", []))
    
    if not script_values:
        warnings.append(
            "No active 'script-src' or 'default-src' directives. "
            "Scripts can be loaded from any source without restriction."
        )
        return warnings

    # 1. Wildcard check
    wildcards = ["*", "http:", "https:", "data:", "http://*", "https://*"]
    for val in script_values:
        if val in wildcards:
            warnings.append(
                f"Wildcard '{val}' detected in script sources. "
                "This allows execution of scripts from arbitrary domains or insecure protocols."
            )

    # 2. Unsafe inline/eval checks
    has_nonce = any(val.startswith("nonce-") for val in script_values)
    has_hash = any(
        val.startswith("sha256-") or val.startswith("sha384-") or val.startswith("sha512-")
        for val in script_values
    )
    
    if "unsafe-inline" in script_values:
        if not (has_nonce or has_hash):
            warnings.append(
                "'unsafe-inline' enabled without nonces or hashes. "
                "This disables inline script restriction and leaves the site vulnerable to XSS."
            )
            
    if "unsafe-eval" in script_values:
        warnings.append(
            "'unsafe-eval' enabled. This allows dynamic Javascript execution "
            "(e.g., eval(), setTimeout()) and significantly weakens XSS protection."
        )

    # 3. Known CDN Bypasses
    # CDNs that host vulnerable libraries (like old AngularJS) or expose JSONP endpoints
    known_cdns = [
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        "unpkg.com",
        "code.jquery.com",
        "google-analytics.com"
    ]
    
    for val in script_values:
        for cdn in known_cdns:
            if cdn in val:
                warnings.append(
                    f"CDN origin '{val}' is trusted in script sources. "
                    "Attackers can leverage hosted libraries (e.g., old AngularJS) or JSONP "
                    "endpoints on this CDN to bypass CSP restrictions."
                )

    # 4. Critical directives missing
    # object-src prevents loading malicious Flash/Java applets
    if "object-src" not in directives:
        warnings.append(
            "Missing 'object-src' directive. This allows embedding malicious "
            "ActiveX/Flash/Java plugins that can execute arbitrary code."
        )
    elif "none" not in directives["object-src"]:
        warnings.append(
            "'object-src' is not set to 'none'. Restrict plugin objects to prevent "
            "plugin-based attacks."
        )

    # base-uri prevents base-tag hijacking of relative paths
    if "base-uri" not in directives:
        warnings.append(
            "Missing 'base-uri' directive. Attackers can inject a <base> tag "
            "to hijack relative URLs and force loading of malicious scripts."
        )
    elif "self" not in directives["base-uri"] and "none" not in directives["base-uri"]:
        warnings.append(
            "'base-uri' is not restricted to 'self' or 'none'. This makes the site "
            "vulnerable to base-tag hijacking."
        )

    return warnings
