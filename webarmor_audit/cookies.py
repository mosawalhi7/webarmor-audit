"""
Cookie security analyzer for WebArmor-Audit.

Parses ``Set-Cookie`` headers from the HTTP response and evaluates each
cookie against security best practices (Secure, HttpOnly, SameSite flags,
cookie name prefixes, and session vs. persistent classification).
"""

from __future__ import annotations


from typing import List, Optional

from webarmor_audit.models import CookieFinding


# ---------------------------------------------------------------------------
# Cookie attribute extraction helpers
# ---------------------------------------------------------------------------

def _extract_flag(attributes: List[str], flag_name: str) -> bool:
    """Return True if *flag_name* appears as a boolean flag in *attributes*."""
    return any(attr.strip().lower() == flag_name.lower() for attr in attributes)


def _extract_attribute(attributes: List[str], attr_name: str) -> Optional[str]:
    """
    Return the value of *attr_name* from *attributes*, or ``None`` if it
    is not present.

    Handles both ``key=value`` and bare-flag forms.
    """
    prefix = f"{attr_name.lower()}="
    for attr in attributes:
        stripped = attr.strip().lower()
        if stripped.startswith(prefix):
            return attr.strip().split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Single cookie analysis
# ---------------------------------------------------------------------------

_VALID_SAMESITE_VALUES = {"strict", "lax", "none"}


def _analyse_single_cookie(
    name: str,
    raw_value: str,
    attributes: List[str],
    is_https: bool,
) -> CookieFinding:
    """
    Evaluate a single cookie's security posture.

    Args:
        name:       The cookie name (before the ``=``).
        raw_value:  The full raw ``Set-Cookie`` header value.
        attributes: Semicolon-split list of cookie attributes (after name=value).
        is_https:   Whether the target URL uses HTTPS.

    Returns:
        A :class:`CookieFinding` with issues populated.
    """
    issues: List[str] = []

    has_secure = _extract_flag(attributes, "Secure")
    has_httponly = _extract_flag(attributes, "HttpOnly")

    # SameSite -----------------------------------------------------------
    samesite_raw = _extract_attribute(attributes, "SameSite")
    has_samesite = samesite_raw is not None
    samesite_value = samesite_raw.strip() if samesite_raw else ""

    # Path / Domain ------------------------------------------------------
    path = _extract_attribute(attributes, "Path") or ""
    domain = _extract_attribute(attributes, "Domain") or ""

    # Session vs. persistent ---------------------------------------------
    has_expires = _extract_attribute(attributes, "Expires") is not None
    has_max_age = _extract_attribute(attributes, "Max-Age") is not None
    is_session = not has_expires and not has_max_age

    # Cookie name prefix -------------------------------------------------
    has_secure_prefix = name.startswith("__Secure-") or name.startswith("__Host-")

    # ---- Issue checks --------------------------------------------------

    if is_https and not has_secure:
        issues.append("Missing 'Secure' flag — cookie may be sent over unencrypted HTTP.")
    elif not is_https and has_secure:
        issues.append("Secure flag set on insecure HTTP connection")

    if not has_httponly:
        issues.append("Missing 'HttpOnly' flag — cookie is accessible via JavaScript (XSS risk).")

    if not has_samesite:
        issues.append("Missing 'SameSite' attribute — vulnerable to CSRF attacks.")
    elif samesite_value.lower() not in _VALID_SAMESITE_VALUES:
        issues.append(
            f"Invalid SameSite value '{samesite_value}'. "
            f"Expected: Strict, Lax, or None."
        )
    elif samesite_value.lower() == "none" and not has_secure:
        issues.append(
            "SameSite=None requires the 'Secure' flag to be set."
        )

    if has_secure_prefix and not has_secure:
        issues.append(
            f"Cookie name '{name}' uses a security prefix but lacks the 'Secure' flag."
        )

    if name.startswith("__Host-"):
        if path != "/":
            issues.append(
                "__Host- prefix requires Path=/ attribute."
            )
        if domain:
            issues.append(
                "__Host- prefix must not have a Domain attribute."
            )

    return CookieFinding(
        name=name,
        has_secure=has_secure,
        has_httponly=has_httponly,
        has_samesite=has_samesite,
        samesite_value=samesite_value,
        has_secure_prefix=has_secure_prefix,
        path=path,
        domain=domain,
        is_session=is_session,
        raw_value=raw_value,
        issues=issues,
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def analyse_cookies(
    set_cookie_headers: List[str],
    is_https: bool = True,
) -> List[CookieFinding]:
    """
    Analyse all ``Set-Cookie`` headers from an HTTP response.

    Args:
        set_cookie_headers: Raw ``Set-Cookie`` header value strings.
        is_https:           Whether the target URL uses HTTPS.

    Returns:
        A list of :class:`CookieFinding` objects, one per cookie.
    """
    findings: List[CookieFinding] = []

    for raw in set_cookie_headers:
        if not raw or "=" not in raw.split(";")[0]:
            continue

        parts = raw.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=", 1)[0].strip()
        attributes = parts[1:] if len(parts) > 1 else []

        finding = _analyse_single_cookie(
            name=name,
            raw_value=raw,
            attributes=attributes,
            is_https=is_https,
        )
        findings.append(finding)

    return findings
