"""
Server information leakage detector for WebArmor-Audit.

Scans HTTP response headers for technology disclosure — web server names,
framework versions, CMS identifiers, and other metadata that attackers
can use for fingerprinting and targeted exploits.
"""

from __future__ import annotations

import re
from typing import Dict, List

from webarmor_audit.models import LeakageInfo


# ---------------------------------------------------------------------------
# Leakage-prone headers and their remediation advice
# ---------------------------------------------------------------------------

# Maps header names to (severity, recommendation_template).
# The recommendation template may contain ``{header}`` and ``{value}``
# placeholders that will be formatted at runtime.

_LEAKAGE_HEADERS: Dict[str, tuple] = {
    "Server": (
        "Medium",
        "Remove or genericise the 'Server' header to avoid revealing "
        "web server software and version. "
        "Apache: 'ServerTokens Prod'. Nginx: 'server_tokens off;'.",
    ),
    "X-Powered-By": (
        "High",
        "Remove the 'X-Powered-By' header entirely. "
        "It exposes the backend framework/language (e.g. PHP, Express, ASP.NET). "
        "In Express: app.disable('x-powered-by'). In PHP: expose_php = Off.",
    ),
    "X-AspNet-Version": (
        "High",
        "Remove 'X-AspNet-Version' by adding "
        "<httpRuntime enableVersionHeader=\"false\" /> in web.config.",
    ),
    "X-AspNetMvc-Version": (
        "High",
        "Remove 'X-AspNetMvc-Version' by calling "
        "MvcHandler.DisableMvcResponseHeader = true in Application_Start().",
    ),
    "X-Generator": (
        "Medium",
        "Remove the 'X-Generator' header to hide CMS/framework information. "
        "In WordPress: add remove_action('wp_head', 'wp_generator').",
    ),
    "X-Drupal-Cache": (
        "Low",
        "Consider removing 'X-Drupal-Cache' to avoid confirming Drupal usage.",
    ),
    "X-Varnish": (
        "Low",
        "Consider removing 'X-Varnish' to avoid confirming caching layer details.",
    ),
    "X-Pingback": (
        "Low",
        "Remove 'X-Pingback' to reduce WordPress fingerprinting surface.",
    ),
}

# Regex to detect version-like patterns (e.g. "2.4.52", "8.1.2", "6.3")
_VERSION_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+)*")

# Severity ranking for sorting
_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _contains_version(value: str) -> bool:
    """Return True if the header value contains a version-like number."""
    return bool(_VERSION_PATTERN.search(value))


def _classify_server_severity(value: str) -> str:
    """
    Upgrade the severity of the Server header if it leaks a version number.

    A bare ``Server: nginx`` is Medium; ``Server: nginx/1.25.3`` is High.
    """
    return "High" if _contains_version(value) else "Medium"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def detect_leakage(response_headers: Dict[str, str]) -> List[LeakageInfo]:
    """
    Scan *response_headers* for information-leaking headers.

    Returns a list of :class:`LeakageInfo` findings sorted by severity
    (High → Medium → Low).
    """
    findings: List[LeakageInfo] = []

    # Normalise to case-insensitive lookup while preserving original keys.
    normalised = {k.lower(): (k, v) for k, v in response_headers.items()}

    for header_name, (base_severity, recommendation) in _LEAKAGE_HEADERS.items():
        entry = normalised.get(header_name.lower())
        if entry is None:
            continue

        original_key, value = entry

        # Refine severity for the Server header based on version exposure.
        if header_name == "Server":
            severity = _classify_server_severity(value)
        else:
            severity = base_severity

        findings.append(
            LeakageInfo(
                header_name=original_key,
                value=value,
                severity=severity,
                recommendation=recommendation,
            )
        )

    # Sort by severity (High first) then header name alphabetically.
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.header_name))

    return findings
