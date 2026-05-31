"""
HTTP security header analysis engine for WebArmor-Audit.

Fetches response headers from a target URL and evaluates each security
header against best-practice configurations, producing scored results.
"""

from __future__ import annotations

import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from webarmor_audit.constants import DEFAULT_TIMEOUT, SECURITY_HEADERS, USER_AGENT
from webarmor_audit.exceptions import ConnectionError, InvalidURLError, TimeoutError
from webarmor_audit.models import HeaderResult


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """
    Validate and normalise the target URL.

    Ensures the URL has a scheme (defaults to ``https://``) and a valid
    hostname.  Returns the normalised URL string.

    Raises:
        InvalidURLError: If the URL cannot be parsed or has no hostname.
    """
    if not url:
        raise InvalidURLError(url, "URL cannot be empty")

    # Prepend scheme when missing so urlparse behaves correctly.
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        raise InvalidURLError(url, "Unable to extract hostname from URL")

    # Quick DNS sanity check — fail fast if the host doesn't resolve.
    try:
        socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise InvalidURLError(url, f"Hostname '{parsed.hostname}' does not resolve")

    return url


# ---------------------------------------------------------------------------
# Header fetching
# ---------------------------------------------------------------------------

def fetch_headers(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> Tuple[Dict[str, str], int, str, str, List[str], requests.Response]:
    """
    Perform an HTTP GET and return relevant response metadata.

    Returns:
        A tuple of (headers_dict, status_code, server_banner, remote_ip,
        set_cookie_list, response).  *set_cookie_list* contains the raw
        ``Set-Cookie`` values so cookies can be analysed individually.

    Raises:
        ConnectionError: On network-level failures.
        TimeoutError:    When the request exceeds *timeout* seconds.
    """
    headers_to_send = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        response = requests.get(
            url,
            headers=headers_to_send,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )
    except requests.exceptions.Timeout:
        raise TimeoutError(url, timeout)
    except requests.exceptions.SSLError as exc:
        raise ConnectionError(url, f"SSL verification failed: {exc}")
    except requests.exceptions.ConnectionError as exc:
        raise ConnectionError(url, str(exc))
    except requests.exceptions.RequestException as exc:
        raise ConnectionError(url, str(exc))

    resp_headers: Dict[str, str] = dict(response.headers)
    status_code: int = response.status_code
    server: str = response.headers.get("Server", "N/A")

    # Extract raw Set-Cookie headers (requests collapses duplicates).
    set_cookie_list: List[str] = []
    if hasattr(response.raw, "_original_response") and response.raw._original_response:
        raw_headers = response.raw._original_response.msg.get_all("Set-Cookie") or []
        set_cookie_list = list(raw_headers)
    elif "Set-Cookie" in response.headers:
        # Fallback: use the collapsed value (may merge multiple cookies).
        set_cookie_list = [response.headers["Set-Cookie"]]

    # Attempt to resolve the IP for informational display.
    remote_ip = "N/A"
    try:
        hostname = urlparse(url).hostname
        if hostname:
            remote_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    return resp_headers, status_code, server, remote_ip, set_cookie_list, response


# ---------------------------------------------------------------------------
# Individual header analysis helpers
# ---------------------------------------------------------------------------

def _analyse_csp(value: Optional[str], meta: dict) -> Tuple[bool, int, str]:
    """Evaluate Content-Security-Policy header value."""
    if value is None:
        return False, 0, "Add a Content-Security-Policy header with at least 'default-src' directive."

    directives = [d.strip().split()[0] for d in value.split(";") if d.strip()]
    has_default = any(d == "default-src" for d in directives)
    has_script = any(d == "script-src" for d in directives)
    uses_unsafe = "'unsafe-inline'" in value or "'unsafe-eval'" in value

    if has_default and has_script and not uses_unsafe:
        return True, meta["weight"], ""
    elif has_default:
        deduction = meta["weight"] // 4 if uses_unsafe else 0
        recommendation = ""
        if uses_unsafe:
            recommendation = "Avoid 'unsafe-inline' and 'unsafe-eval' in CSP directives."
        if not has_script:
            recommendation += " Consider adding an explicit 'script-src' directive."
        return True, meta["weight"] - deduction, recommendation.strip()
    else:
        return True, meta["weight"] // 2, "CSP is present but missing 'default-src' directive."


def _analyse_hsts(value: Optional[str], meta: dict) -> Tuple[bool, int, str]:
    """Evaluate Strict-Transport-Security header value."""
    if value is None:
        return False, 0, "Add Strict-Transport-Security with max-age >= 31536000."

    parts = [p.strip().lower() for p in value.split(";")]

    max_age_val = 0
    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age_val = int(part.split("=")[1])
            except (ValueError, IndexError):
                pass

    if max_age_val == 0:
        return True, meta["weight"] // 4, "HSTS max-age is missing or zero."

    has_subdomains = any("includesubdomains" in p for p in parts)
    has_preload = any("preload" in p for p in parts)

    score = meta["weight"]
    recommendations: list[str] = []

    if max_age_val < 31536000:
        score -= meta["weight"] // 4
        recommendations.append("Increase max-age to at least 31536000 (1 year).")
    if not has_subdomains:
        score -= 2
        recommendations.append("Add 'includeSubDomains' directive.")
    if not has_preload:
        score -= 1
        recommendations.append("Consider adding 'preload' directive.")

    return True, max(score, 0), " ".join(recommendations)


def _analyse_simple_header(
    value: Optional[str],
    meta: dict,
    header_name: str,
) -> Tuple[bool, int, str]:
    """
    Evaluate a header whose validity is determined by matching against
    a list of known-good values (X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy).
    """
    if value is None:
        return False, 0, f"Add the {header_name} header. Recommended: {meta['recommended']}"

    valid_values = meta.get("valid_values", [])
    if valid_values and value.strip().lower() not in [v.lower() for v in valid_values]:
        return (
            True,
            meta["weight"] // 2,
            f"'{value}' is not a recommended value. Use one of: {', '.join(valid_values)}",
        )

    return True, meta["weight"], ""


def _analyse_referrer_policy(value: Optional[str], meta: dict) -> Tuple[bool, int, str]:
    """
    Evaluate Referrer-Policy header value.

    The Referrer-Policy specification allows multiple comma-separated
    values as a fallback list — the browser picks the last value it
    understands.  We validate each individual token.
    """
    if value is None:
        return False, 0, f"Add the Referrer-Policy header. Recommended: {meta['recommended']}"

    valid_values = [v.lower() for v in meta.get("valid_values", [])]
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]

    if not tokens:
        return True, 0, f"Referrer-Policy header is empty. Recommended: {meta['recommended']}"

    # Check if ALL tokens are recognised valid values.
    invalid_tokens = [t for t in tokens if t not in valid_values]

    if not invalid_tokens:
        return True, meta["weight"], ""

    # Some tokens are unrecognised — partial score.
    valid_count = len(tokens) - len(invalid_tokens)
    if valid_count > 0:
        # At least one valid value exists; mild deduction for the unknowns.
        deduction = (len(invalid_tokens) * meta["weight"]) // (len(tokens) * 2)
        return (
            True,
            meta["weight"] - deduction,
            f"Unrecognised value(s): {', '.join(invalid_tokens)}. "
            f"Valid options: {', '.join(meta.get('valid_values', []))}",
        )

    return (
        True,
        meta["weight"] // 2,
        f"'{value}' is not a recommended value. Use one of: {', '.join(meta.get('valid_values', []))}",
    )


def _analyse_permissions_policy(value: Optional[str], meta: dict) -> Tuple[bool, int, str]:
    """Evaluate Permissions-Policy header value."""
    if value is None:
        return False, 0, "Add a Permissions-Policy header to restrict browser features."

    expected_directives = meta.get("directives", [])
    present_directives = [d.strip().split("=")[0] for d in value.split(",") if "=" in d]

    missing = [d for d in expected_directives if d not in present_directives]

    if not missing:
        return True, meta["weight"], ""

    deduction = (len(missing) * meta["weight"]) // (len(expected_directives) + 1)
    return (
        True,
        meta["weight"] - deduction,
        f"Consider restricting: {', '.join(missing)}.",
    )


# ---------------------------------------------------------------------------
# Public analysis interface
# ---------------------------------------------------------------------------

_ANALYSERS = {
    "Content-Security-Policy": _analyse_csp,
    "Strict-Transport-Security": _analyse_hsts,
    "X-Frame-Options": lambda v, m: _analyse_simple_header(v, m, "X-Frame-Options"),
    "X-Content-Type-Options": lambda v, m: _analyse_simple_header(v, m, "X-Content-Type-Options"),
    "Referrer-Policy": _analyse_referrer_policy,
    "Permissions-Policy": _analyse_permissions_policy,
}


def analyse_headers(response_headers: Dict[str, str]) -> List[HeaderResult]:
    """
    Analyse all tracked security headers against the response.

    Returns a list of :class:`HeaderResult` objects, one per header
    defined in :data:`SECURITY_HEADERS`.
    """
    results: List[HeaderResult] = []

    # Normalise response header keys to lower-case for case-insensitive lookup.
    normalised: Dict[str, Tuple[str, str]] = {
        k.lower(): (k, v) for k, v in response_headers.items()
    }

    for header_name, meta in SECURITY_HEADERS.items():
        raw_value: Optional[str] = None
        entry = normalised.get(header_name.lower())
        if entry is not None:
            raw_value = entry[1]

        analyser = _ANALYSERS.get(header_name)
        if analyser is None:
            # Fallback for any header without a dedicated analyser.
            is_valid, score, recommendation = _analyse_simple_header(
                raw_value, meta, header_name
            )
        else:
            is_valid, score, recommendation = analyser(raw_value, meta)

        results.append(
            HeaderResult(
                name=header_name,
                present=raw_value is not None,
                value=raw_value,
                is_valid=is_valid,
                score=score,
                max_score=meta["weight"],
                recommendation=recommendation,
                description=meta["description"],
            )
        )

    return results
