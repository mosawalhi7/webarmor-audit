"""
Grading algorithm for WebArmor-Audit.

Computes a numeric score from individual header results and maps it to a
letter grade (A+ through F) using the thresholds defined in
:mod:`webarmor_audit.constants`.
"""

from __future__ import annotations

from typing import List, Tuple

from webarmor_audit.constants import GRADE_THRESHOLDS
from webarmor_audit.models import AuditReport, HeaderResult


def compute_score(header_results: List[HeaderResult]) -> Tuple[int, int]:
    """
    Sum the individual header scores and their max possible values.

    Returns:
        (total_score, max_score)
    """
    total = sum(h.score for h in header_results)
    maximum = sum(h.max_score for h in header_results)
    return total, maximum


def assign_grade(score: int, max_score: int) -> str:
    """
    Map a raw score to a letter grade.

    The percentage ``(score / max_score) * 100`` is evaluated against
    :data:`GRADE_THRESHOLDS` in descending order.
    """
    if max_score == 0:
        return "F"

    percentage = (score / max_score) * 100

    for threshold, grade in GRADE_THRESHOLDS:
        if percentage >= threshold:
            return grade

    return "F"


def build_summary(grade: str, report: AuditReport) -> str:
    """
    Generate a one-line human-readable summary of the audit result.
    """
    present = sum(1 for h in report.headers if h.present)
    total = len(report.headers)

    if grade in ("A+", "A"):
        verdict = "Excellent security posture"
    elif grade == "B":
        verdict = "Good security posture with minor improvements possible"
    elif grade == "C":
        verdict = "Moderate security posture — several headers need attention"
    elif grade == "D":
        verdict = "Weak security posture — critical headers are missing"
    else:
        verdict = "Poor security posture — immediate action recommended"

    return (
        f"{verdict}. "
        f"{present}/{total} security headers detected. "
        f"Score: {report.total_score}/{report.max_score} ({report.score_percentage}%)."
    )


def collect_recommendations(report: AuditReport) -> List[str]:
    """
    Gather actionable recommendations from header results, cookie
    findings, information leakage, CORS, security.txt, CSP bypasses,
    and redirect chain issues. Incorporates CWE/OWASP mapping standards.
    """
    from webarmor_audit.constants import CWE_OWASP_MAPPING
    recs: List[str] = []

    # Header-level recommendations.
    for header in report.headers:
        if header.recommendation:
            mapping = CWE_OWASP_MAPPING.get(header.name, {"cwe": "N/A", "owasp": "N/A"})
            recs.append(
                f"[{header.name}] {header.recommendation} "
                f"(CWE: {mapping['cwe']} | OWASP: {mapping['owasp']})"
            )

    # Cookie-level recommendations.
    cookies_without_secure = [c.name for c in report.cookie_findings if not c.has_secure]
    cookies_without_httponly = [c.name for c in report.cookie_findings if not c.has_httponly]
    cookies_without_samesite = [c.name for c in report.cookie_findings if not c.has_samesite]

    cookie_mapping = CWE_OWASP_MAPPING.get("Cookie Security", {"cwe": "N/A", "owasp": "N/A"})
    mapping_suffix = f" (CWE: {cookie_mapping['cwe']} | OWASP: {cookie_mapping['owasp']})"

    if cookies_without_secure:
        names = ", ".join(cookies_without_secure[:3])
        suffix = f" (+{len(cookies_without_secure) - 3} more)" if len(cookies_without_secure) > 3 else ""
        recs.append(f"[Cookie Security] Add 'Secure' flag to: {names}{suffix}{mapping_suffix}")
    if cookies_without_httponly:
        names = ", ".join(cookies_without_httponly[:3])
        suffix = f" (+{len(cookies_without_httponly) - 3} more)" if len(cookies_without_httponly) > 3 else ""
        recs.append(f"[Cookie Security] Add 'HttpOnly' flag to: {names}{suffix}{mapping_suffix}")
    if cookies_without_samesite:
        names = ", ".join(cookies_without_samesite[:3])
        suffix = f" (+{len(cookies_without_samesite) - 3} more)" if len(cookies_without_samesite) > 3 else ""
        recs.append(f"[Cookie Security] Add 'SameSite' attribute to: {names}{suffix}{mapping_suffix}")

    # Leakage recommendations.
    leak_mapping = CWE_OWASP_MAPPING.get("Information Leakage", {"cwe": "N/A", "owasp": "N/A"})
    for leak in report.leakage_findings:
        recs.append(f"[Info Leakage] {leak.recommendation} (CWE: {leak_mapping['cwe']} | OWASP: {leak_mapping['owasp']})")

    # CORS recommendations.
    cors_mapping = CWE_OWASP_MAPPING.get("CORS Audit", {"cwe": "N/A", "owasp": "N/A"})
    for cors in report.cors_findings:
        if cors.recommendation:
            recs.append(f"[CORS] {cors.recommendation} (CWE: {cors_mapping['cwe']} | OWASP: {cors_mapping['owasp']})")

    # security.txt recommendations.
    if report.security_txt_finding and report.security_txt_finding.recommendation:
        recs.append(f"[security.txt] {report.security_txt_finding.recommendation}")

    # CSP Bypass recommendations.
    csp_mapping = CWE_OWASP_MAPPING.get("CSP Bypass", {"cwe": "N/A", "owasp": "N/A"})
    for warn in report.csp_bypass_warnings:
        recs.append(f"[CSP Bypass] {warn} (CWE: {csp_mapping['cwe']} | OWASP: {csp_mapping['owasp']})")

    # Redirect chain checks
    redirect_mapping = CWE_OWASP_MAPPING.get("Redirect Chain", {"cwe": "N/A", "owasp": "N/A"})
    has_seen_https = False
    for hop in report.redirect_chain:
        if hop.is_https:
            has_seen_https = True
        elif has_seen_https and not hop.is_https:
            recs.append(
                f"[Redirects] Downgrade Redirect: Secure HTTPS connection was downgraded "
                f"to insecure HTTP protocol at target '{hop.url}'. "
                f"(CWE: {redirect_mapping['cwe']} | OWASP: {redirect_mapping['owasp']})"
            )

    # SSL/TLS active scanning checks
    ssl_mapping = CWE_OWASP_MAPPING.get("SSL/TLS Config", {"cwe": "N/A", "owasp": "N/A"})
    if report.ssl_info:
        ssl_info = report.ssl_info
        if ssl_info.has_tls10_or_below:
            recs.append(
                f"[SSL/TLS Protocol] Deprecated Protocols Supported: The server supports legacy TLS 1.0 or TLS 1.1 "
                f"protocols. Enforce TLS 1.2 or TLS 1.3 as the minimum requirement. "
                f"(CWE: {ssl_mapping['cwe']} | OWASP: {ssl_mapping['owasp']})"
            )
        if ssl_info.has_weak_ciphers:
            ciphers_str = ", ".join(ssl_info.supported_weak_ciphers)
            recs.append(
                f"[SSL/TLS Ciphers] Weak Cipher Suites Supported: The server accepts weak/vulnerable cipher suites: "
                f"{ciphers_str}. Disable RC4, 3DES, EXPORT, and anonymous/NULL ciphers to prevent BEAST/SWEET32 attacks. "
                f"(CWE: {ssl_mapping['cwe']} | OWASP: {ssl_mapping['owasp']})"
            )

    # Fuzzing Exposure Recommendations
    for fuzz in report.fuzz_findings:
        if fuzz.is_exposed:
            recs.append(
                f"[Sensitive Exposure] Exposed path '{fuzz.path}' detected on web server. "
                f"Description: {fuzz.description} Remediation: {fuzz.remediation} "
                f"(CWE: CWE-200 | OWASP: A01:2021-Broken Access Control)"
            )

    return recs

