"""
Rich CLI interface for WebArmor-Audit.

Orchestrates the full audit pipeline — URL validation, header fetching,
analysis, SSL inspection, cookie audit, leakage detection, grading,
terminal output, and report generation.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from webarmor_audit import __version__
from webarmor_audit.constants import DEFAULT_REPORT_FILENAME, DEFAULT_TIMEOUT
from webarmor_audit.cookies import analyse_cookies
from webarmor_audit.exceptions import WebArmorError
from webarmor_audit.grader import assign_grade, build_summary, collect_recommendations, compute_score
from webarmor_audit.headers import analyse_headers, fetch_headers, validate_url
from webarmor_audit.leakage import detect_leakage
from webarmor_audit.models import AuditReport
from webarmor_audit.reporter import generate_report
from webarmor_audit.ssl_info import fetch_ssl_info

# Package imports
from webarmor_audit.config import load_config, apply_profile
from webarmor_audit.cache import get_cached_report, save_to_cache
from webarmor_audit.cors import evaluate_cors
from webarmor_audit.security_txt import audit_security_txt
from webarmor_audit.protocols import audit_protocols
from webarmor_audit.csp_evaluator import evaluate_csp_bypass
from webarmor_audit.redirects import audit_redirect_chain
from webarmor_audit.reporter import (
    generate_json_report,
    generate_html_report,
    generate_sarif_report,
    report_to_dict,
    generate_json_bulk_summary,
    generate_html_bulk_summary,
)

console = Console()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Create and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="webarmor-audit",
        description=(
            "WebArmor-Audit — Audit HTTP security headers and SSL/TLS "
            "certificate configuration for any URL."
        ),
        epilog="Example: webarmor-audit https://example.com -o report.md",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Target URL to audit (e.g. https://example.com).",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_REPORT_FILENAME,
        help=f"Output path for the report (default: {DEFAULT_REPORT_FILENAME}).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Skip SSL certificate inspection.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification for the HTTP request.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "json", "html", "sarif"],
        default="markdown",
        help="Output report format (default: markdown).",
    )
    parser.add_argument(
        "--fail-under",
        choices=["A+", "A", "B", "C", "D", "F"],
        help="Exit with code 2 if the overall grade is below this threshold.",
    )
    parser.add_argument(
        "--fail-score",
        type=float,
        help="Exit with code 2 if the overall score percentage is below this threshold (0-100).",
    )
    parser.add_argument(
        "-b", "--bulk",
        help="Path to a text file containing target URLs (one per line) for concurrent bulk scanning.",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to a custom TOML profile configuration file (e.g. config.toml).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable retrieving results from cache.",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=300,
        help="Cache TTL in seconds (default: 300).",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


# ---------------------------------------------------------------------------
# CLI display helpers
# ---------------------------------------------------------------------------

GRADE_STYLES = {
    "A+": "bold bright_green",
    "A": "bold green",
    "B": "bold yellow",
    "C": "bold dark_orange",
    "D": "bold red",
    "F": "bold bright_red",
}


def _print_banner() -> None:
    """Display the application banner."""
    banner_text = Text(justify="center")
    banner_text.append("WebArmor-Audit\n", style="bold bright_white")
    banner_text.append("HTTP Security Headers & SSL Auditor", style="dim white")

    panel = Panel(
        banner_text,
        border_style="cyan",
        box=box.DOUBLE,
        expand=False,
        padding=(0, 4)
    )
    console.print(panel)
    console.print()


def _print_target_info(report: AuditReport) -> None:
    """Display the target info panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()
    table.add_row("Target URL", report.url)
    table.add_row("IP Address", report.ip_address)
    table.add_row("HTTP Status", str(report.status_code))
    table.add_row("Server", report.server)
    table.add_row("Scan Time", report.timestamp)

    console.print(Panel(table, title="[bold]Target Information[/bold]", border_style="blue", box=box.ROUNDED))
    console.print()


def _print_headers_table(report: AuditReport) -> None:
    """Display the security headers analysis table."""
    table = Table(
        title="Security Headers Analysis",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold bright_white",
        title_style="bold cyan",
    )
    table.add_column("Header", style="bold white", min_width=28)
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Score", justify="center", min_width=8)
    table.add_column("Value", max_width=40)

    for h in report.headers:
        if not h.present:
            status = Text("❌ MISSING", style="bold red")
        elif h.is_valid and h.score == h.max_score:
            status = Text("✅ PASS", style="bold green")
        elif h.is_valid:
            status = Text("🟡 PARTIAL", style="bold yellow")
        else:
            status = Text("🟡 WARN", style="bold yellow")

        score_style = "green" if h.score == h.max_score else ("yellow" if h.score > 0 else "red")
        score_text = Text(f"{h.score}/{h.max_score}", style=score_style)

        value_display = h.value[:45] + "…" if h.value and len(h.value) > 45 else (h.value or "—")

        table.add_row(h.name, status, score_text, value_display)

    console.print(table)
    console.print()


def _print_ssl_info(report: AuditReport) -> None:
    """Display SSL certificate information."""
    if report.ssl_info is None:
        return

    ssl = report.ssl_info

    if ssl.error:
        console.print(
            Panel(
                f"[bold red]Error:[/bold red] {ssl.error}",
                title="[bold]SSL/TLS Certificate[/bold]",
                border_style="red",
                box=box.ROUNDED,
            )
        )
        console.print()
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()

    cert_status = "[bold green]Valid ✅[/bold green]" if ssl.is_valid else "[bold red]Expired / Invalid ❌[/bold red]"
    table.add_row("Status", cert_status)
    table.add_row("Issuer", ssl.issuer)
    table.add_row("Subject", ssl.subject)

    not_before = ssl.not_before.strftime("%Y-%m-%d %H:%M UTC") if ssl.not_before else "N/A"
    not_after = ssl.not_after.strftime("%Y-%m-%d %H:%M UTC") if ssl.not_after else "N/A"
    table.add_row("Valid From", not_before)
    table.add_row("Valid Until", not_after)

    days_style = "green" if ssl.days_remaining > 30 else ("yellow" if ssl.days_remaining > 7 else "red")
    table.add_row("Days Remaining", f"[{days_style}]{ssl.days_remaining}[/{days_style}]")

    console.print(Panel(table, title="[bold]🔒 SSL/TLS Certificate[/bold]", border_style="green", box=box.ROUNDED))
    console.print()

    # Active Protocol Scan Table
    proto_table = Table(
        title="Active SSL/TLS Protocol Support",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold bright_white",
        title_style="bold cyan",
    )
    proto_table.add_column("Protocol Version", style="bold white", min_width=25)
    proto_table.add_column("Support Status", justify="center", min_width=25)

    for v in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]:
        if v in ssl.supported_tls_versions:
            status = Text("✔ Supported", style="bold green")
        elif v in ssl.rejected_tls_versions:
            status = Text("✘ Rejected", style="bold red")
        else:
            status = Text("— Local Client Limit", style="dim white")
        proto_table.add_row(v, status)

    console.print(proto_table)
    console.print()

    # Legacy Weak Ciphers Test Table
    ciphers_table = Table(
        title="Legacy Weak Ciphers Test Matrix",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold bright_white",
        title_style="bold magenta",
    )
    ciphers_table.add_column("Cipher Suite Group", style="bold white", min_width=25)
    ciphers_table.add_column("Security Status", justify="center", min_width=25)

    for wc in ["RC4", "3DES", "aNULL", "eNULL", "EXPORT"]:
        is_supported = wc in ssl.supported_weak_ciphers
        if is_supported:
            status = Text("⚠ VULNERABLE", style="bold red")
        else:
            status = Text("✔ SECURE (Rejected)", style="bold green")
        ciphers_table.add_row(wc, status)

    console.print(ciphers_table)
    console.print()


def _print_cookie_audit(report: AuditReport) -> None:
    """Display the cookie security audit results."""
    findings = report.cookie_findings

    if not findings:
        console.print(
            Panel(
                "[dim]No cookies were set by the target server.[/dim]",
                title="[bold]🍪 Cookie Security Audit[/bold]",
                border_style="dim",
                box=box.ROUNDED,
            )
        )
        console.print()
        return

    table = Table(
        title="Cookie Security Audit",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold bright_white",
        title_style="bold magenta",
    )
    table.add_column("Cookie Name", style="bold white", min_width=20, max_width=30)
    table.add_column("Secure", justify="center", min_width=8)
    table.add_column("HttpOnly", justify="center", min_width=10)
    table.add_column("SameSite", justify="center", min_width=10)
    table.add_column("Issues", justify="center", min_width=8)

    for c in findings:
        secure_icon = Text("✅", style="green") if c.has_secure else Text("❌", style="red")
        httponly_icon = Text("✅", style="green") if c.has_httponly else Text("❌", style="red")

        if c.has_samesite:
            samesite_icon = Text(f"✅ {c.samesite_value}", style="green")
        else:
            samesite_icon = Text("❌", style="red")

        issue_count = c.issue_count
        if issue_count == 0:
            issue_text = Text("0", style="bold green")
        else:
            issue_text = Text(str(issue_count), style="bold red")

        name_display = c.name[:28] + "…" if len(c.name) > 28 else c.name

        table.add_row(name_display, secure_icon, httponly_icon, samesite_icon, issue_text)

    console.print(table)

    # Print detailed issues below the table.
    cookies_with_issues = [c for c in findings if c.issues]
    if cookies_with_issues:
        console.print()
        console.print("[bold magenta]  🔎 Cookie Issues Detail:[/bold magenta]")
        for c in cookies_with_issues:
            console.print(f"   [bold]{c.name}[/bold]")
            for issue in c.issues:
                console.print(f"      [dim]•[/dim] [yellow]{issue}[/yellow]")

    # Summary line.
    total = len(findings)
    secure_count = sum(1 for c in findings if c.is_fully_protected)
    console.print()
    console.print(
        f"  [dim]Summary:[/dim] "
        f"[bold]{secure_count}/{total}[/bold] cookies fully protected"
    )
    console.print()


def _print_leakage_warnings(report: AuditReport) -> None:
    """Display server information leakage warnings."""
    findings = report.leakage_findings

    if not findings:
        console.print(
            Panel(
                "[bold green]No server information leakage detected.[/bold green]",
                title="[bold]🔍 Information Leakage[/bold]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        console.print()
        return

    table = Table(
        title="Information Leakage Detection",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold bright_white",
        title_style="bold red",
    )
    table.add_column("Header", style="bold white", min_width=22)
    table.add_column("Leaked Value", min_width=25, max_width=45)
    table.add_column("Severity", justify="center", min_width=10)

    severity_styles = {
        "High": "bold bright_red",
        "Medium": "bold yellow",
        "Low": "dim white",
    }

    for leak in findings:
        style = severity_styles.get(leak.severity, "white")
        sev_text = Text(f"⚠ {leak.severity}", style=style)
        value_display = leak.value[:42] + "…" if len(leak.value) > 42 else leak.value

        table.add_row(leak.header_name, value_display, sev_text)

    console.print(table)
    console.print()


def _print_fuzz_findings(report: AuditReport) -> None:
    """Display smart fuzzer findings on console."""
    findings = report.fuzz_findings
    if not findings:
        return

    exposed = [f for f in findings if f.is_exposed]
    if not exposed:
        console.print(
            Panel(
                "[bold green]No exposed sensitive paths or configuration backups discovered.[/bold green]",
                title="[bold]📂 Smart Path Fuzzing[/bold]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        console.print()
        return

    table = Table(
        title="Exposed sensitive directories / configuration backups",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold bright_white",
        title_style="bold red",
    )
    table.add_column("Scanned Path", style="bold white", min_width=22)
    table.add_column("HTTP Status", justify="center", min_width=12)
    table.add_column("Exposure Status", justify="center", min_width=18)
    table.add_column("Severity", justify="center", min_width=12)

    severity_styles = {
        "High": "bold bright_red",
        "Medium": "bold yellow",
        "Low": "dim white",
    }

    for fuzz in exposed:
        style = severity_styles.get(fuzz.severity, "white")
        sev_text = Text(fuzz.severity, style=style)
        status_text = Text("🔴 EXPOSED", style="bold red")
        table.add_row(fuzz.path, str(fuzz.status_code), status_text, sev_text)

    console.print(table)
    console.print()


def _print_grade(report: AuditReport) -> None:
    """Display the overall grade panel."""
    style = GRADE_STYLES.get(report.grade, "bold white")
    grade_text = Text(f"  {report.grade}  ", style=style)

    inner = Table(show_header=False, box=None, padding=(0, 1))
    inner.add_column(justify="center")
    inner.add_row(grade_text)
    inner.add_row(Text(f"Score: {report.total_score}/{report.max_score} ({report.score_percentage}%)", style="white"))

    grade_border = "green" if report.grade.startswith("A") else (
        "yellow" if report.grade == "B" else (
            "dark_orange" if report.grade == "C" else "red"
        )
    )

    console.print(Panel(inner, title="[bold]Overall Grade[/bold]", border_style=grade_border, box=box.DOUBLE))
    console.print()


def _print_recommendations(report: AuditReport) -> None:
    """Display recommendations if any exist."""
    if not report.recommendations:
        console.print("[bold green]✅ No recommendations — your security headers look great![/bold green]\n")
        return

    console.print("[bold cyan]💡 Recommendations:[/bold cyan]")
    for idx, rec in enumerate(report.recommendations, start=1):
        console.print(f"   [dim]{idx}.[/dim] {rec}")
    console.print()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def dict_to_report(data: Dict[str, Any]) -> AuditReport:
    """Helper to recreate AuditReport from deserialized JSON cache."""
    from webarmor_audit.models import HeaderResult, SSLInfo, CookieFinding, LeakageInfo, CORSEvaluation, SecurityTxtFinding, RedirectHop
    
    ssl_data = data.get("ssl_info")
    ssl_info = None
    if ssl_data:
        ssl_info = SSLInfo(
            issuer=ssl_data.get("issuer", "N/A"),
            subject=ssl_data.get("subject", "N/A"),
            serial_number=ssl_data.get("serial_number", "N/A"),
            not_before=datetime.fromisoformat(ssl_data["not_before"]) if ssl_data.get("not_before") else None,
            not_after=datetime.fromisoformat(ssl_data["not_after"]) if ssl_data.get("not_after") else None,
            days_remaining=ssl_data.get("days_remaining", -1),
            version=ssl_data.get("version", 0),
            is_valid=ssl_data.get("is_valid", False),
            error=ssl_data.get("error"),
            supported_tls_versions=ssl_data.get("supported_tls_versions", []),
            rejected_tls_versions=ssl_data.get("rejected_tls_versions", []),
            supported_weak_ciphers=ssl_data.get("supported_weak_ciphers", []),
            has_tls10_or_below=ssl_data.get("has_tls10_or_below", False),
            has_weak_ciphers=ssl_data.get("has_weak_ciphers", False)
        )
        
    headers = [HeaderResult(**h) for h in data.get("headers", [])]
    cookies = []
    for c in data.get("cookie_findings", []):
        c_copy = dict(c)
        c_copy.pop("is_fully_protected", None)
        cookies.append(CookieFinding(**c_copy))
    leakage = [LeakageInfo(**l) for l in data.get("leakage_findings", [])]
    cors = [CORSEvaluation(**cors_data) for cors_data in data.get("cors_findings", [])]
    
    sec_data = data.get("security_txt_finding")
    sec_finding = None
    if sec_data:
        sec_finding = SecurityTxtFinding(
            present=sec_data.get("present", False),
            url_checked=sec_data.get("url_checked", ""),
            status_code=sec_data.get("status_code", 0),
            has_contact=sec_data.get("has_contact", False),
            has_expires=sec_data.get("has_expires", False),
            is_expired=sec_data.get("is_expired", False),
            expires_date=sec_data.get("expires_date"),
            issues=sec_data.get("issues", []),
            recommendation=sec_data.get("recommendation", "")
        )
        
    redirects = [RedirectHop(**r) for r in data.get("redirect_chain", [])]
    
    from webarmor_audit.models import FuzzFinding, WAFDetails
    fuzz_findings = [FuzzFinding(**f) for f in data.get("fuzz_findings", [])]
    
    waf_data = data.get("waf_details")
    waf_details = None
    if waf_data:
        waf_details = WAFDetails(
            detected=waf_data.get("detected", False),
            waf_name=waf_data.get("waf_name", "None"),
            reason=waf_data.get("reason", ""),
            signature_type=waf_data.get("signature_type", "None")
        )

    return AuditReport(
        url=data["url"],
        timestamp=data.get("timestamp", ""),
        ip_address=data.get("ip_address", "N/A"),
        server=data.get("server", "N/A"),
        status_code=data.get("status_code", 0),
        headers=headers,
        ssl_info=ssl_info,
        total_score=data.get("total_score", 0),
        max_score=data.get("max_score", 100),
        grade=data.get("grade", "F"),
        summary=data.get("summary", ""),
        recommendations=data.get("recommendations", []),
        raw_headers=data.get("raw_headers", {}),
        cookie_findings=cookies,
        leakage_findings=leakage,
        cors_findings=cors,
        security_txt_finding=sec_finding,
        supported_protocols=data.get("supported_protocols", []),
        redirect_chain=redirects,
        csp_bypass_warnings=data.get("csp_bypass_warnings", []),
        fuzz_findings=fuzz_findings,
        waf_details=waf_details
    )


def save_output_report(report: AuditReport, filepath: str, fmt: str) -> None:
    """Generate and save report file based on format choice."""
    if fmt == "json":
        generate_json_report(report, filepath)
    elif fmt == "html":
        generate_html_report(report, filepath)
    elif fmt == "sarif":
        generate_sarif_report(report, filepath)
    else:
        generate_report(report, filepath)


def perform_single_audit(url: str, args: argparse.Namespace, silent: bool = False) -> AuditReport:
    """Execute the full auditing workflow for a single URL target."""
    if not silent:
        console.print(f"[bold cyan]➜[/bold cyan] Validating target URL: {url}…")
        
    url = validate_url(url)
    
    # 1. Caching Check
    if not args.no_cache:
        cached = get_cached_report(url, ttl_seconds=args.cache_ttl)
        if cached:
            if not silent:
                console.print(f"[bold green]✔[/bold green] Retrieved cached result for {url}")
            return dict_to_report(cached)

    if not silent:
        console.print("[bold cyan]➜[/bold cyan] Fetching HTTP response headers…")
        
    raw_headers, status_code, server, ip_addr, set_cookie_list, response = fetch_headers(
        url, timeout=args.timeout, verify_ssl=not args.insecure
    )

    if not silent:
        console.print(f"[dim]  Received {len(raw_headers)} headers (HTTP {status_code})[/dim]\n")
        console.print("[bold cyan]➜[/bold cyan] Analysing security headers…")
        
    header_results = analyse_headers(raw_headers)

    if not silent:
        console.print("[bold cyan]➜[/bold cyan] Auditing cookie security…")
        
    is_https = url.startswith("https://")
    cookie_findings = analyse_cookies(set_cookie_list, is_https=is_https)

    if not silent:
        cookie_count = len(cookie_findings)
        issue_count = sum(c.issue_count for c in cookie_findings)
        if cookie_count > 0:
            console.print(f"[dim]  Found {cookie_count} cookie(s), {issue_count} issue(s)[/dim]")
        else:
            console.print("[dim]  No cookies detected[/dim]")
        console.print("[bold cyan]➜[/bold cyan] Scanning for information leakage…")
        
    leakage_findings = detect_leakage(raw_headers)

    if not silent:
        if leakage_findings:
            console.print(f"[dim]  Detected {len(leakage_findings)} leaking header(s)[/dim]")
        else:
            console.print("[dim]  No information leakage found[/dim]")

    # Advanced Audits
    cors_findings = evaluate_cors(raw_headers)
    security_txt_finding = audit_security_txt(url, timeout=args.timeout, verify_ssl=not args.insecure)
    supported_protocols = audit_protocols(url, raw_headers, timeout=args.timeout)
    redirect_chain, redirect_warnings = audit_redirect_chain(response)
    
    csp_header = raw_headers.get("Content-Security-Policy", "")
    csp_bypass_warnings = evaluate_csp_bypass(csp_header)

    # Active WAF Fingerprinting
    from webarmor_audit.waf import detect_waf
    waf_details = detect_waf(raw_headers, set_cookie_list)
    if waf_details.detected and not silent:
        console.print(f"[bold yellow]🛡️  [WAF Detected: {waf_details.waf_name} Is Active][/bold yellow]")
        console.print(f"   [dim]Reason: {waf_details.reason}[/dim]\n")

    # Sensitive path fuzzing
    if not silent:
        console.print("[bold cyan]➜[/bold cyan] Probing for sensitive and exposed configuration directories (Smart Fuzzing)…")
    from webarmor_audit.fuzzer import run_smart_fuzz
    fuzz_findings = run_smart_fuzz(url, timeout=args.timeout, verify_ssl=not args.insecure)
    if not silent:
        exposed = [f for f in fuzz_findings if f.is_exposed]
        if exposed:
            console.print(f"   [bold red]⚠ Exposed Sensitive Paths Found: {len(exposed)}[/bold red]")
        else:
            console.print("   [dim]No sensitive files exposed[/dim]")
        console.print()

    ssl_info = None
    if not args.no_ssl and url.startswith("https://"):
        if not silent:
            console.print("[bold cyan]➜[/bold cyan] Retrieving SSL certificate info…")
        ssl_info = fetch_ssl_info(url, timeout=args.timeout)

    total_score, max_score = compute_score(header_results)
    grade = assign_grade(total_score, max_score)

    report = AuditReport(
        url=url,
        timestamp=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        ip_address=ip_addr,
        server=server,
        status_code=status_code,
        headers=header_results,
        ssl_info=ssl_info,
        total_score=total_score,
        max_score=max_score,
        grade=grade,
        raw_headers=raw_headers,
        cookie_findings=cookie_findings,
        leakage_findings=leakage_findings,
        cors_findings=cors_findings,
        security_txt_finding=security_txt_finding,
        supported_protocols=supported_protocols,
        redirect_chain=redirect_chain,
        csp_bypass_warnings=csp_bypass_warnings,
        fuzz_findings=fuzz_findings,
        waf_details=waf_details
    )
    report.summary = build_summary(grade, report)
    report.recommendations = collect_recommendations(report)

    # Save to Cache
    if not args.no_cache:
        save_to_cache(url, report_to_dict(report))

    return report


def check_thresholds(report: AuditReport, args: argparse.Namespace) -> bool:
    """
    Check if a report fails specified fail-under or fail-score thresholds.
    
    Returns True if the report VIOLATES the threshold (meaning failure).
    """
    GRADE_RANKS = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    
    if args.fail_under:
        target_rank = GRADE_RANKS.get(args.fail_under.upper(), 1)
        report_rank = GRADE_RANKS.get(report.grade.upper(), 1)
        if report_rank < target_rank:
            return True
            
    if args.fail_score is not None:
        if report.score_percentage < args.fail_score:
            return True
            
    return False


def run(argv: list[str] | None = None) -> int:
    """
    Execute the full audit pipeline.

    Returns:
        0 on success.
        1 on initialization, config, or invalid input errors.
        2 on threshold violations (fail-under / fail-score).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Enforce URL or Bulk arg constraints
    if not args.bulk and not args.url:
        console.print("[bold red]Error:[/bold red] You must specify a target URL or a URL list file using -b/--bulk.")
        return 1

    _print_banner()

    # Load custom config profile if provided
    if args.config:
        try:
            profile = load_config(args.config)
            apply_profile(profile)
            console.print(f"[bold green]✔[/bold green] Successfully loaded audit profile: {args.config}\n")
        except Exception as e:
            console.print(f"[bold red]✗ Configuration Error:[/bold red] {e}")
            return 1

    if args.bulk:
        # --- BULK SCANNING WORKFLOW ---
        if not os.path.exists(args.bulk):
            console.print(f"[bold red]Error:[/bold red] Bulk URLs file not found: {args.bulk}")
            return 1
            
        with open(args.bulk, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith(("#", ";"))]
            
        if not urls:
            console.print("[bold red]Error:[/bold red] No valid URLs discovered in bulk file.")
            return 1
            
        console.print(f"🚀 Starting concurrent bulk audit of [bold]{len(urls)}[/bold] targets...\n")
        
        reports: List[AuditReport] = []
        failed_threshold = False
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(perform_single_audit, url, args, True): url for url in urls}
            
            for future in futures:
                url = futures[future]
                try:
                    report = future.result()
                    reports.append(report)
                    
                    # Output individual report
                    parsed_url = urlparse(url)
                    host_sanitized = parsed_url.hostname.replace(".", "_") if parsed_url.hostname else "target"
                    base, ext = os.path.splitext(args.output)
                    individual_output = f"{base}_{host_sanitized}{ext}"
                    save_output_report(report, individual_output, args.format)
                    
                    # Print summary CLI line
                    style = GRADE_STYLES.get(report.grade, "bold white")
                    console.print(
                        f"  [[{style}]{report.grade}[/{style}]] "
                        f"[bold]{url}[/bold] — Score: {report.total_score}/{report.max_score} "
                        f"({report.score_percentage}%) → Saved to [underline]{individual_output}[/underline]"
                    )
                    
                    # Check threshold for each report
                    if check_thresholds(report, args):
                        failed_threshold = True
                        
                except Exception as e:
                    console.print(f"  [bold red]✗ Fail:[/bold red] {url} — Error: {e}")
                    
        # Generate combined bulk summary report based on format
        if args.format == "html":
            generate_html_bulk_summary(reports, args.output)
        elif args.format == "json":
            generate_json_bulk_summary(reports, args.output)
        else:
            # Fallback to Markdown format
            now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            summary_lines = [
                "# 🛡️ WebArmor-Audit — Bulk Scan Summary\n",
                f"> **Generated:** {now}  ",
                f"> **Total Targets:** {len(reports)} / {len(urls)}\n",
                "---\n",
                "## 📊 Target Results\n",
                "| Target URL | Grade | Score | Resolved IP | Status Code | Report File |",
                "| --- | :---: | :---: | --- | :---: | --- |"
            ]
            
            for r in reports:
                parsed_url = urlparse(r.url)
                host_sanitized = parsed_url.hostname.replace(".", "_") if parsed_url.hostname else "target"
                base, ext = os.path.splitext(args.output)
                file_ref = f"{os.path.basename(base)}_{host_sanitized}{ext}"
                summary_lines.append(
                    f"| [`{r.url}`]({r.url}) | **{r.grade}** | {r.total_score}/{r.max_score} "
                    f"({r.score_percentage}%) | `{r.ip_address}` | {r.status_code} | [`{file_ref}`]({file_ref}) |"
                )
                
            summary_content = "\n".join(summary_lines)
            abs_output_path = os.path.abspath(args.output)
            os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)
            with open(abs_output_path, "w", encoding="utf-8") as f:
                f.write(summary_content)
            
        console.print(
            f"\n[bold green]🎉 Bulk scan complete![/bold green] "
            f"Summary report generated at: [underline]{args.output}[/underline]\n"
        )
        
        if failed_threshold:
            console.print("[bold red]✗ Security Gate Failed:[/bold red] One or more targets did not meet the defined threshold.")
            return 2
            
        return 0

    else:
        # --- SINGLE TARGET SCANNIG WORKFLOW ---
        try:
            report = perform_single_audit(args.url, args, False)
        except WebArmorError as exc:
            console.print(f"[bold red]✗ Error:[/bold red] {exc}")
            return 1
            
        console.print()

        # Display results on terminal
        _print_target_info(report)
        _print_headers_table(report)
        _print_cookie_audit(report)
        _print_leakage_warnings(report)
        _print_fuzz_findings(report)
        _print_ssl_info(report)
        _print_grade(report)
        _print_recommendations(report)

        # Generate report file
        save_output_report(report, args.output, args.format)
        console.print(
            f"[bold green]📄 Report ({args.format}) saved to:[/bold green] "
            f"[underline]{args.output}[/underline]\n"
        )

        # Check threshold
        if check_thresholds(report, args):
            console.print("[bold red]✗ Security Gate Failed:[/bold red] Target did not meet the defined threshold.")
            return 2

        return 0
