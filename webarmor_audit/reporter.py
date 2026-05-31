"""
Report generator for WebArmor-Audit.

Supports Markdown, JSON, HTML (responsive dark mode), and SARIF formats.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from webarmor_audit.constants import DEFAULT_REPORT_FILENAME
from webarmor_audit.models import AuditReport, CORSEvaluation, RedirectHop, SecurityTxtFinding


def _grade_emoji(grade: str) -> str:
    """Map a letter grade to a descriptive emoji."""
    mapping = {
        "A+": "🛡️",
        "A": "✅",
        "B": "👍",
        "C": "⚠️",
        "D": "🔶",
        "F": "❌",
    }
    return mapping.get(grade, "❓")


def _header_status_icon(present: bool, is_valid: bool) -> str:
    """Return a Markdown-friendly status icon for a header."""
    if not present:
        return "❌ Missing"
    return "✅ Present" if is_valid else "⚠️ Misconfigured"


def _format_date(dt: Optional[datetime]) -> str:
    """Format a datetime for display, or return 'N/A'."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def report_to_dict(report: AuditReport) -> Dict[str, Any]:
    """Convert AuditReport dataclass to a JSON-serializable dictionary."""
    return {
        "url": report.url,
        "timestamp": report.timestamp,
        "ip_address": report.ip_address,
        "server": report.server,
        "status_code": report.status_code,
        "total_score": report.total_score,
        "max_score": report.max_score,
        "score_percentage": report.score_percentage,
        "grade": report.grade,
        "summary": report.summary,
        "recommendations": report.recommendations,
        "raw_headers": report.raw_headers,
        "headers": [
            {
                "name": h.name,
                "present": h.present,
                "value": h.value,
                "is_valid": h.is_valid,
                "score": h.score,
                "max_score": h.max_score,
                "recommendation": h.recommendation,
                "description": h.description
            } for h in report.headers
        ],
        "ssl_info": {
            "issuer": report.ssl_info.issuer,
            "subject": report.ssl_info.subject,
            "serial_number": report.ssl_info.serial_number,
            "not_before": report.ssl_info.not_before.isoformat() if report.ssl_info.not_before else None,
            "not_after": report.ssl_info.not_after.isoformat() if report.ssl_info.not_after else None,
            "days_remaining": report.ssl_info.days_remaining,
            "version": report.ssl_info.version,
            "is_valid": report.ssl_info.is_valid,
            "error": report.ssl_info.error,
            "supported_tls_versions": report.ssl_info.supported_tls_versions,
            "rejected_tls_versions": report.ssl_info.rejected_tls_versions,
            "supported_weak_ciphers": report.ssl_info.supported_weak_ciphers,
            "has_tls10_or_below": report.ssl_info.has_tls10_or_below,
            "has_weak_ciphers": report.ssl_info.has_weak_ciphers
        } if report.ssl_info else None,
        "cookie_findings": [
            {
                "name": c.name,
                "has_secure": c.has_secure,
                "has_httponly": c.has_httponly,
                "has_samesite": c.has_samesite,
                "samesite_value": c.samesite_value,
                "has_secure_prefix": c.has_secure_prefix,
                "path": c.path,
                "domain": c.domain,
                "is_session": c.is_session,
                "raw_value": c.raw_value,
                "issues": c.issues,
                "is_fully_protected": c.is_fully_protected
            } for c in report.cookie_findings
        ],
        "leakage_findings": [
            {
                "header_name": l.header_name,
                "value": l.value,
                "severity": l.severity,
                "recommendation": l.recommendation
            } for l in report.leakage_findings
        ],
        "cors_findings": [
            {
                "header_name": cors.header_name,
                "value": cors.value,
                "is_secure": cors.is_secure,
                "issues": cors.issues,
                "recommendation": cors.recommendation
            } for cors in report.cors_findings
        ],
        "security_txt_finding": {
            "present": report.security_txt_finding.present,
            "url_checked": report.security_txt_finding.url_checked,
            "status_code": report.security_txt_finding.status_code,
            "has_contact": report.security_txt_finding.has_contact,
            "has_expires": report.security_txt_finding.has_expires,
            "is_expired": report.security_txt_finding.is_expired,
            "expires_date": report.security_txt_finding.expires_date,
            "issues": report.security_txt_finding.issues,
            "recommendation": report.security_txt_finding.recommendation
        } if report.security_txt_finding else None,
        "supported_protocols": report.supported_protocols,
        "redirect_chain": [
            {
                "url": r.url,
                "status_code": r.status_code,
                "is_https": r.is_https,
                "headers": r.headers
            } for r in report.redirect_chain
        ],
        "csp_bypass_warnings": report.csp_bypass_warnings,
        "fuzz_findings": [
            {
                "path": f.path,
                "status_code": f.status_code,
                "is_exposed": f.is_exposed,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation
            } for f in report.fuzz_findings
        ],
        "waf_details": {
            "detected": report.waf_details.detected,
            "waf_name": report.waf_details.waf_name,
            "reason": report.waf_details.reason,
            "signature_type": report.waf_details.signature_type
        } if report.waf_details else None
    }


def generate_json_report(report: AuditReport, output_path: str) -> str:
    """Render report as JSON and write to disk."""
    data = report_to_dict(report)
    content = json.dumps(data, indent=2, ensure_ascii=False)
    
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)
        
    return content


def generate_sarif_report(report: AuditReport, output_path: str) -> str:
    """
    Render report as GitHub Code Scanning compatible SARIF v2.1.0 JSON.
    """
    rules = []
    results = []

    # Map headers to WA-00X rules
    for idx, h in enumerate(report.headers, start=1):
        rule_id = f"WA-00{idx}"
        rules.append({
            "id": rule_id,
            "name": f"HeaderCheck-{h.name}",
            "shortDescription": {"text": f"HTTP Security Header: {h.name}"},
            "helpUri": "https://owasp.org/www-project-secure-headers/"
        })
        if not h.present or not h.is_valid:
            results.append({
                "ruleId": rule_id,
                "message": {
                    "text": f"Header '{h.name}' is missing or misconfigured. Recommendation: {h.recommendation or h.description}"
                },
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.url}
                    }
                }]
            })

    # Rule WA-101: SSL Cert validity
    rules.append({
        "id": "WA-101",
        "name": "SSLCertificateValidity",
        "shortDescription": {"text": "SSL/TLS certificate validity check."}
    })
    if report.ssl_info and (report.ssl_info.error or not report.ssl_info.is_valid):
        results.append({
            "ruleId": "WA-101",
            "message": {
                "text": f"SSL certificate is invalid or returned an error: {report.ssl_info.error or 'Expired'}"
            },
            "level": "error",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-102: Deprecated TLS Protocols
    rules.append({
        "id": "WA-102",
        "name": "DeprecatedTLSProtocols",
        "shortDescription": {"text": "Deprecated TLS protocol versions enabled."}
    })
    if report.ssl_info and report.ssl_info.has_tls10_or_below:
        results.append({
            "ruleId": "WA-102",
            "message": {
                "text": "The server supports deprecated TLS 1.0 or TLS 1.1 protocols, which are cryptographically weak and vulnerable to downgrade attacks."
            },
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-103: Weak Cipher Suites
    rules.append({
        "id": "WA-103",
        "name": "WeakCipherSuites",
        "shortDescription": {"text": "Weak or broken cipher suites enabled."}
    })
    if report.ssl_info and report.ssl_info.has_weak_ciphers:
        results.append({
            "ruleId": "WA-103",
            "message": {
                "text": f"The server supports weak or legacy cipher suites: {', '.join(report.ssl_info.supported_weak_ciphers)}."
            },
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-201: Cookie security flags
    rules.append({
        "id": "WA-201",
        "name": "CookieSecurityFlags",
        "shortDescription": {"text": "Insecure cookie flags (HttpOnly/Secure/SameSite)."}
    })
    for c in report.cookie_findings:
        if c.issues:
            results.append({
                "ruleId": "WA-201",
                "message": {
                    "text": f"Cookie '{c.name}' has security issues: {'; '.join(c.issues)}"
                },
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.url}
                    }
                }]
            })

    # Rule WA-301: Server leakage info
    rules.append({
        "id": "WA-301",
        "name": "ServerInformationLeakage",
        "shortDescription": {"text": "Exposure of server configuration in HTTP headers."}
    })
    for leak in report.leakage_findings:
        results.append({
            "ruleId": "WA-301",
            "message": {
                "text": f"Header '{leak.header_name}' exposes platform information: {leak.value}. Severity: {leak.severity}."
            },
            "level": "note" if leak.severity == "Low" else "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-401: CORS evaluation
    rules.append({
        "id": "WA-401",
        "name": "CORSConfigAudit",
        "shortDescription": {"text": "Permissive or dangerous CORS configurations."}
    })
    for cors in report.cors_findings:
        if not cors.is_secure or cors.issues:
            results.append({
                "ruleId": "WA-401",
                "message": {
                    "text": f"CORS Configuration Risk in '{cors.header_name}': {'; '.join(cors.issues)}"
                },
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.url}
                    }
                }]
            })

    # Rule WA-501: security.txt
    rules.append({
        "id": "WA-501",
        "name": "SecurityTxtPresence",
        "shortDescription": {"text": "Missing or invalid security.txt file (RFC 9116)."}
    })
    if report.security_txt_finding and (not report.security_txt_finding.present or report.security_txt_finding.issues):
        results.append({
            "ruleId": "WA-501",
            "message": {
                "text": f"security.txt file is missing or invalid: {'; '.join(report.security_txt_finding.issues)}"
            },
            "level": "note",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-601: Redirect downgrade
    rules.append({
        "id": "WA-601",
        "name": "RedirectDowngrade",
        "shortDescription": {"text": "Redirect chain contains HTTP protocol downgrades."}
    })
    # Filter warning list for downgrades
    downgrade_warnings = [w for w in report.recommendations if "Downgrade" in w or "downgrade" in w.lower()]
    for warn in downgrade_warnings:
        results.append({
            "ruleId": "WA-601",
            "message": {"text": warn},
            "level": "error",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    # Rule WA-701: CSP bypass warnings
    rules.append({
        "id": "WA-701",
        "name": "CSPBypassCheck",
        "shortDescription": {"text": "Content-Security-Policy contains exploitable bypasses."}
    })
    for warn in report.csp_bypass_warnings:
        results.append({
            "ruleId": "WA-701",
            "message": {"text": f"CSP Bypass Warning: {warn}"},
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.url}
                }
            }]
        })

    sarif_data = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WebArmor-Audit",
                    "informationUri": "https://github.com/webarmor/webarmor-audit",
                    "version": "1.0.0",
                    "rules": rules
                }
            },
            "results": results
        }]
    }

    content = json.dumps(sarif_data, indent=2, ensure_ascii=False)
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

    return content


def generate_html_report(report: AuditReport, output_path: str) -> str:
    """
    Render report as a premium single-page HTML file with a responsive dark-neon dashboard design.
    """
    # Map grade to color accents
    accent_colors = {
        "A+": "#10b981", # green
        "A": "#059669",
        "B": "#fbbf24",  # amber
        "C": "#f59e0b",  # orange
        "D": "#ef4444",  # red
        "F": "#dc2626"
    }
    accent = accent_colors.get(report.grade, "#3b82f6")

    # Format headers
    headers_rows = []
    for h in report.headers:
        status_cls = "pass" if h.present and h.is_valid else ("warn" if h.present else "fail")
        status_txt = "PASS" if h.present and h.is_valid else ("WARN" if h.present else "MISSING")
        val = h.value or "—"
        if len(val) > 70:
            val = f"<span title='{val}'>{val[:70]}...</span>"
        from webarmor_audit.constants import CWE_OWASP_MAPPING
        mapping = CWE_OWASP_MAPPING.get(h.name, {"cwe": "N/A", "owasp": "N/A"})
        headers_rows.append(f"""
        <tr>
            <td><strong>{h.name}</strong></td>
            <td><span class='badge {status_cls}'>{status_txt}</span></td>
            <td><code>{val}</code></td>
            <td><small><code>{mapping['cwe']}</code><br><span style='color: var(--text-muted); font-size: 0.75rem;'>{mapping['owasp']}</span></small></td>
            <td class='score-cell'>{h.score}/{h.max_score}</td>
        </tr>
        """)

    # Format cookies
    cookies_rows = []
    for c in report.cookie_findings:
        sec = "✅" if c.has_secure else "❌"
        httponly = "✅" if c.has_httponly else "❌"
        samesite = f"✅ ({c.samesite_value})" if c.has_samesite else "❌"
        cookies_rows.append(f"""
        <tr>
            <td><code>{c.name}</code></td>
            <td align="center">{sec}</td>
            <td align="center">{httponly}</td>
            <td align="center">{samesite}</td>
            <td align="center"><strong>{c.issue_count}</strong></td>
        </tr>
        """)
        
    # Format leakage
    leakage_rows = []
    for l in report.leakage_findings:
        sev_cls = l.severity.lower()
        leakage_rows.append(f"""
        <tr>
            <td><strong>{l.header_name}</strong></td>
            <td><code>{l.value}</code></td>
            <td><span class='badge {sev_cls}'>{l.severity}</span></td>
        </tr>
        """)

    # Advanced security checks formatting
    # Fuzz findings formatting
    fuzz_html = ""
    if report.fuzz_findings:
        fuzz_html = """
        <div class="card">
            <h3>📂 Smart Path Fuzzing Exposure Analysis</h3>
            <table class="report-table">
                <thead>
                    <tr><th>Scanned Path</th><th>Status</th><th>Exposure Status</th><th>Severity</th><th>Description</th></tr>
                </thead>
                <tbody>
        """
        for fuzz in report.fuzz_findings:
            status_cls = "fail" if fuzz.is_exposed else "pass"
            status_txt = "EXPOSED" if fuzz.is_exposed else "SECURE"
            fuzz_html += f"<tr><td><code>{fuzz.path}</code></td><td>{fuzz.status_code}</td><td><span class='badge {status_cls}'>{status_txt}</span></td><td><span class='badge {fuzz.severity.lower()}'>{fuzz.severity}</span></td><td><small>{fuzz.description}</small></td></tr>"
        fuzz_html += "</tbody></table></div>"
    else:
        fuzz_html = "<div class='card'><h3>📂 Smart Path Fuzzing Analysis</h3><p class='dim'>Fuzzing was not run or target is secure.</p></div>"

    # CORS
    cors_html = ""
    if report.cors_findings:
        cors_html = "<h4>CORS Headers Analysis</h4><table class='report-table'><thead><tr><th>Header</th><th>Value</th><th>Security Status</th></tr></thead><tbody>"
        for cors in report.cors_findings:
            status_cls = "pass" if cors.is_secure else "fail"
            status_txt = "SECURE" if cors.is_secure else "VULNERABLE"
            issues_txt = f"<div class='error-msg'>{'<br>'.join(cors.issues)}</div>" if cors.issues else ""
            cors_html += f"<tr><td><strong>{cors.header_name}</strong></td><td><code>{cors.value}</code></td><td><span class='badge {status_cls}'>{status_txt}</span>{issues_txt}</td></tr>"
        cors_html += "</tbody></table>"
    else:
        cors_html = "<p class='dim'>CORS response headers were not detected on this endpoint.</p>"

    # security.txt
    sectxt_html = ""
    if report.security_txt_finding:
        st = report.security_txt_finding
        status_cls = "pass" if st.present and not st.issues else ("warn" if st.present else "fail")
        status_txt = "VALID" if st.present and not st.issues else ("PARTIAL / ISSUES" if st.present else "MISSING")
        issues_txt = ""
        if st.issues:
            issues_txt = "<ul>" + "".join(f"<li>⚠️ {issue}</li>" for issue in st.issues) + "</ul>"
            
        sectxt_html = f"""
        <div class="card">
            <h4>security.txt Alignment</h4>
            <p><strong>Path Checked:</strong> <code>{st.url_checked}</code></p>
            <p><strong>Status:</strong> <span class="badge {status_cls}">{status_txt}</span></p>
            {issues_txt}
            {f"<p class='rec-msg'>💡 {st.recommendation}</p>" if st.recommendation else ""}
        </div>
        """

    # Protocols
    protocols_html = ""
    proto_badges = "".join(f"<span class='badge info'>{proto}</span> " for proto in report.supported_protocols)
    protocols_html = f"""
    <div class="card">
        <h4>HTTP Protocols Supported</h4>
        <div style="margin: 10px 0;">{proto_badges}</div>
        <p class="dim">HTTP/2 support is active if ALPN negotiation succeeds. HTTP/3 checks rely on Alt-Svc headers.</p>
    </div>
    """

    # Redirect Chain
    redirects_html = ""
    if report.redirect_chain:
        redirects_html = "<h4>HTTP Redirection Path</h4><table class='report-table'><thead><tr><th>Step</th><th>URL</th><th>Status Code</th><th>HTTPS</th></tr></thead><tbody>"
        for i, hop in enumerate(report.redirect_chain, start=1):
            sec_icon = "✅ Secure" if hop.is_https else "❌ Insecure (HTTP)"
            sec_cls = "pass" if hop.is_https else "fail"
            redirects_html += f"<tr><td>{i}</td><td><code>{hop.url}</code></td><td>{hop.status_code}</td><td><span class='badge {sec_cls}'>{sec_icon}</span></td></tr>"
        redirects_html += "</tbody></table>"
    else:
        redirects_html = "<p class='dim'>No HTTP redirects occurred. The URL was reached directly.</p>"

    # CSP Bypass Warnings
    csp_bypass_html = ""
    if report.csp_bypass_warnings:
        csp_bypass_html = "<div class='card warning-card'><h4>⚠️ CSP Bypass Warning Analysis</h4><ul>"
        for warning in report.csp_bypass_warnings:
            csp_bypass_html += f"<li>{warning}</li>"
        csp_bypass_html += "</ul></div>"

    # SSL Info Card
    ssl_html = "<p class='dim'>No SSL details gathered.</p>"
    if report.ssl_info:
        ssl = report.ssl_info
        if ssl.error:
            ssl_html = f"<div class='badge fail'>SSL Error: {ssl.error}</div>"
        else:
            status_cls = "pass" if ssl.is_valid else "fail"
            
            # active scanning HTML widgets
            tls_supported_badges = "".join(f"<span class='badge pass'>{v}</span> " for v in ssl.supported_tls_versions)
            tls_rejected_badges = "".join(f"<span class='badge fail'>{v}</span> " for v in ssl.rejected_tls_versions)
            
            weak_ciphers_html = ""
            for wc in ["RC4", "3DES", "aNULL", "eNULL", "EXPORT"]:
                is_supported = wc in ssl.supported_weak_ciphers
                badge_cls = "fail" if is_supported else "pass"
                status_txt = "VULNERABLE" if is_supported else "SECURE"
                weak_ciphers_html += f"<tr><td><strong>{wc}</strong></td><td><span class='badge {badge_cls}'>{status_txt}</span></td></tr>"

            ssl_html = f"""
            <table class="report-table">
                <tr><td><strong>Validity Status</strong></td><td><span class="badge {status_cls}">{'Valid' if ssl.is_valid else 'Expired'}</span></td></tr>
                <tr><td><strong>Certificate Issuer</strong></td><td>{ssl.issuer}</td></tr>
                <tr><td><strong>Subject CN</strong></td><td>{ssl.subject}</td></tr>
                <tr><td><strong>Valid From</strong></td><td>{_format_date(ssl.not_before)}</td></tr>
                <tr><td><strong>Expires On</strong></td><td>{_format_date(ssl.not_after)}</td></tr>
                <tr><td><strong>Days Remaining</strong></td><td><strong>{ssl.days_remaining}</strong> days</td></tr>
                <tr><td><strong>Serial Number</strong></td><td><small><code>{ssl.serial_number}</code></small></td></tr>
            </table>
            
            <h5 style="margin-top: 20px; margin-bottom: 10px; color: #fff;">Active SSL/TLS Protocol Support</h5>
            <table class="report-table">
                <tr><td><strong>Supported TLS Versions</strong></td><td>{tls_supported_badges or '<span class="badge fail">None</span>'}</td></tr>
                <tr><td><strong>Rejected TLS Versions</strong></td><td>{tls_rejected_badges or '<span class="badge pass">None</span>'}</td></tr>
            </table>
            
            <h5 style="margin-top: 20px; margin-bottom: 10px; color: #fff;">Legacy Weak Ciphers Test Matrix</h5>
            <table class="report-table">
                <thead>
                    <tr><th>Cipher Group</th><th>Security Status</th></tr>
                </thead>
                <tbody>
                    {weak_ciphers_html}
                </tbody>
            </table>
            """

    # Recommendations
    recs_list = ""
    if report.recommendations:
        recs_list = "<ol class='recs-list'>"
        for r in report.recommendations:
            recs_list += f"<li>{r}</li>"
        recs_list += "</ol>"
    else:
        recs_list = "<p class='pass-msg'>🎉 Excellent job! No security vulnerabilities or configuration gaps were discovered.</p>"

    # HTML Template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebArmor-Audit — Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: {accent};
            --pass-color: #10b981;
            --warn-color: #f59e0b;
            --fail-color: #ef4444;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            margin-bottom: 40px;
            text-align: center;
        }}
        
        h1 {{
            font-weight: 700;
            font-size: 2.5rem;
            margin-bottom: 10px;
            letter-spacing: -1px;
            color: #fff;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .meta-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 15px;
            border-radius: 12px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        
        .meta-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 5px;
        }}
        
        .meta-value {{
            font-weight: 600;
            font-size: 1.1rem;
            word-break: break-all;
        }}
        
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .col-main {{
            grid-column: span 2;
        }}
        
        .col-side {{
            grid-column: span 1;
        }}
        
        @media (max-width: 900px) {{
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
            .col-main, .col-side {{
                grid-column: span 1;
            }}
        }}
        
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
        }}
        
        .grade-card {{
            border-left: 5px solid var(--accent);
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px 25px;
        }}
        
        .big-grade {{
            font-size: 5rem;
            font-weight: 800;
            color: var(--accent);
            line-height: 1;
            text-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
        }}
        
        .score-info {{
            margin-top: 15px;
            font-size: 1.2rem;
            color: var(--text-main);
        }}
        
        .verdict {{
            margin-top: 10px;
            color: var(--text-muted);
            font-style: italic;
        }}
        
        h3, h4 {{
            margin-bottom: 20px;
            color: #fff;
            font-weight: 600;
        }}
        
        h4 {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-top: 15px;
        }}
        
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
            font-size: 0.95rem;
        }}
        
        .report-table th, .report-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .report-table th {{
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-align: center;
        }}
        
        .badge.pass {{ background-color: rgba(16, 185, 129, 0.15); color: var(--pass-color); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge.warn {{ background-color: rgba(245, 158, 11, 0.15); color: var(--warn-color); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge.fail {{ background-color: rgba(239, 68, 68, 0.15); color: var(--fail-color); border: 1px solid rgba(239, 68, 68, 0.3); }}
        
        .badge.high {{ background-color: rgba(239, 68, 68, 0.2); color: var(--fail-color); }}
        .badge.medium {{ background-color: rgba(245, 158, 11, 0.2); color: var(--warn-color); }}
        .badge.low {{ background-color: rgba(255, 255, 255, 0.1); color: var(--text-muted); }}
        .badge.info {{ background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        
        code {{
            font-family: monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 4px;
            color: #f472b6;
            word-break: break-all;
        }}
        
        .dim {{
            color: var(--text-muted);
            font-size: 0.95rem;
            margin: 12px 0;
            display: block;
        }}
        
        .score-cell {{
            font-weight: 600;
            text-align: right !important;
        }}
        
        .recs-list {{
            padding-left: 20px;
        }}
        
        .recs-list li {{
            margin-bottom: 12px;
            color: var(--text-main);
        }}
        
        .error-msg {{
            color: var(--warn-color);
            font-size: 0.8rem;
            margin-top: 5px;
            font-family: monospace;
        }}
        
        .warning-card {{
            border: 1px solid rgba(245, 158, 11, 0.3);
            background: rgba(245, 158, 11, 0.05);
        }}
        
        .warning-card li {{
            color: var(--warn-color);
            margin-bottom: 8px;
            margin-left: 15px;
        }}
        
        .rec-msg {{
            font-size: 0.9rem;
            color: var(--warn-color);
            margin-top: 10px;
        }}
        
        .pass-msg {{
            color: var(--pass-color);
            font-weight: 600;
        }}
        
        footer {{
            text-align: center;
            margin-top: 50px;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
        
        footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ WebArmor-Audit Report</h1>
            <p class="dim">HTTP Security Headers & SSL Posture Scan</p>
            
            <div class="meta-grid">
                <div class="meta-card">
                    <div class="meta-title">Target URL</div>
                    <div class="meta-value">{report.url}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-title">Resolved IP</div>
                    <div class="meta-value">{report.ip_address}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-title">Web Server</div>
                    <div class="meta-value">{report.server}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-title">WAF Firewall</div>
                    <div class="meta-value">{report.waf_details.waf_name if report.waf_details and report.waf_details.detected else 'None Detected'}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-title">Scan Timestamp</div>
                    <div class="meta-value">{report.timestamp}</div>
                </div>
            </div>
        </header>
        
        <div class="dashboard-grid">
            <div class="col-main">
                <div class="card">
                    <h3>📋 Security Headers Analysis</h3>
                    <table class="report-table">
                        <thead>
                            <tr>
                                <th>Header</th>
                                <th>Status</th>
                                <th>Value</th>
                                <th>Standards Mapping</th>
                                <th style="text-align: right;">Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(headers_rows)}
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h3>🛡️ Advanced Security Configurations</h3>
                    {csp_bypass_html}
                    {cors_html}
                    {redirects_html}
                </div>
                
                {fuzz_html}
            </div>
            
            <div class="col-side">
                <div class="card grade-card">
                    <div class="meta-title" style="margin-bottom: 10px;">Postures Grade</div>
                    <div class="big-grade">{report.grade}</div>
                    <div class="score-info">Score: {report.total_score} / {report.max_score} ({report.score_percentage}%)</div>
                    <div class="verdict">{report.summary}</div>
                </div>
                
                <div class="card">
                    <h3>🔒 SSL/TLS Certificate</h3>
                    {ssl_html}
                </div>
                
                {sectxt_html}
                
                {protocols_html}
            </div>
        </div>
        
        <div class="card" style="border-left: 5px solid var(--warn-color);">
            <h3>💡 Remediation & Recommendations Checklist</h3>
            {recs_list}
        </div>
        
        <footer>
            Report generated by <a href="https://github.com/webarmor/webarmor-audit" target="_blank">WebArmor-Audit</a> — Security Auditor.
        </footer>
    </div>
</body>
</html>
"""
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return html_content


def generate_report(report: AuditReport, output_path: Optional[str] = None) -> str:
    """
    Render the audit report as a Markdown string and write to disk.
    """
    emoji = _grade_emoji(report.grade)
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = []

    # Title & meta
    lines.append("# 🛡️ WebArmor-Audit — Security Report\n")
    lines.append(f"> **Generated:** {now}  ")
    lines.append(f"> **Target URL:** `{report.url}`  ")
    lines.append(f"> **Resolved IP:** `{report.ip_address}`  ")
    lines.append(f"> **HTTP Status:** `{report.status_code}`  ")
    lines.append(f"> **Server:** `{report.server}`  ")
    
    waf_txt = "None Detected"
    if report.waf_details and report.waf_details.detected:
        waf_txt = f"⚠️ {report.waf_details.waf_name} ({report.waf_details.reason})"
    lines.append(f"> **WAF Firewall:** `{waf_txt}`\n")

    # Grade summary
    lines.append("---\n")
    lines.append(f"## {emoji} Overall Grade: **{report.grade}**\n")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| **Score** | {report.total_score} / {report.max_score} |")
    lines.append(f"| **Percentage** | {report.score_percentage}% |")
    lines.append(f"| **Grade** | {report.grade} |")
    lines.append("")

    if report.summary:
        lines.append(f"**Summary:** {report.summary}\n")

    # Header details
    lines.append("---\n")
    lines.append("## 📋 Security Headers Analysis\n")
    lines.append("| Header | Status | Value | Score | Standards Mapping |")
    lines.append("| --- | --- | --- | --- | --- |")

    from webarmor_audit.constants import CWE_OWASP_MAPPING
    for h in report.headers:
        status = _header_status_icon(h.present, h.is_valid)
        value_display = f"`{h.value[:60]}…`" if h.value and len(h.value) > 60 else (f"`{h.value}`" if h.value else "—")
        mapping = CWE_OWASP_MAPPING.get(h.name, {"cwe": "N/A", "owasp": "N/A"})
        mapping_str = f"`{mapping['cwe']}` / `{mapping['owasp']}`"
        lines.append(f"| **{h.name}** | {status} | {value_display} | {h.score}/{h.max_score} | {mapping_str} |")

    lines.append("")

    # Detailed header breakdown
    lines.append("### Header Details\n")
    for h in report.headers:
        icon = "✅" if h.present and h.is_valid else ("⚠️" if h.present else "❌")
        lines.append(f"#### {icon} {h.name}\n")
        lines.append(f"- **Description:** {h.description}")
        lines.append(f"- **Present:** {'Yes' if h.present else 'No'}")
        if h.value:
            lines.append(f"- **Value:** `{h.value}`")
        lines.append(f"- **Score:** {h.score}/{h.max_score}")
        if h.recommendation:
            lines.append(f"- **Recommendation:** {h.recommendation}")
        lines.append("")

    # Cookie security analysis
    lines.append("---\n")
    lines.append("## 🍪 Cookie Security Analysis\n")

    if report.cookie_findings:
        total_cookies = len(report.cookie_findings)
        protected = sum(1 for c in report.cookie_findings if c.is_fully_protected)
        lines.append(f"> **{protected}/{total_cookies}** cookies are fully protected (Secure + HttpOnly + SameSite).\n")

        lines.append("| Cookie Name | Secure | HttpOnly | SameSite | Issues |")
        lines.append("| --- | :---: | :---: | :---: | :---: |")

        for c in report.cookie_findings:
            secure = "✅" if c.has_secure else "❌"
            httponly = "✅" if c.has_httponly else "❌"
            samesite = f"✅ `{c.samesite_value}`" if c.has_samesite else "❌"
            issue_count = str(c.issue_count)

            name_display = f"`{c.name[:35]}…`" if len(c.name) > 35 else f"`{c.name}`"
            lines.append(f"| {name_display} | {secure} | {httponly} | {samesite} | {issue_count} |")

        lines.append("")

        # Detailed per-cookie issues.
        cookies_with_issues = [c for c in report.cookie_findings if c.issues]
        if cookies_with_issues:
            lines.append("### Cookie Issue Details\n")
            for c in cookies_with_issues:
                lines.append(f"**`{c.name}`**\n")
                for issue in c.issues:
                    lines.append(f"- ⚠️ {issue}")
                lines.append("")
    else:
        lines.append("> ℹ️ No cookies were set by the target server.\n")

    # CORS evaluation section
    lines.append("---\n")
    lines.append("## 🛡️ CORS Configuration Audit\n")
    if report.cors_findings:
        lines.append("| CORS Header | Value | Secure | Issues |")
        lines.append("| --- | --- | :---: | --- |")
        for cors in report.cors_findings:
            status_icon = "✅" if cors.is_secure else "❌"
            issues_str = "; ".join(cors.issues) if cors.issues else "None"
            lines.append(f"| **{cors.header_name}** | `{cors.value}` | {status_icon} | {issues_str} |")
        lines.append("")
    else:
        lines.append("> ✅ No dangerous CORS headers exposed.\n")

    # security.txt section
    lines.append("---\n")
    lines.append("## 📂 security.txt Alignment (RFC 9116)\n")
    if report.security_txt_finding:
        st = report.security_txt_finding
        if st.present:
            lines.append(f"- **Status:** ✅ Present at `{st.url_checked}`")
            lines.append(f"- **Has Contact:** {'Yes' if st.has_contact else 'No'}")
            lines.append(f"- **Has Expiration:** {'Yes' if st.has_expires else 'No'} (Expires: `{st.expires_date or 'N/A'}`)")
            if st.issues:
                lines.append("- **Compliance Issues:**")
                for issue in st.issues:
                    lines.append(f"  - ⚠️ {issue}")
        else:
            lines.append(f"- **Status:** ❌ Missing (Checked `{st.url_checked}`)")
            if st.recommendation:
                lines.append(f"- **Recommendation:** {st.recommendation}")
        lines.append("")

    # HTTP protocols section
    lines.append("---\n")
    lines.append("## 🌐 Network Protocol Support\n")
    lines.append(f"- **Supported HTTP Versions:** {', '.join(f'`{p}`' for p in report.supported_protocols)}\n")

    # Redirect chain section
    lines.append("---\n")
    lines.append("## 🔄 HTTP Redirection Chain\n")
    if report.redirect_chain:
        lines.append("| Hop | URL | Status | Secure (HTTPS) |")
        lines.append("| --- | --- | :---: | :---: |")
        for idx, hop in enumerate(report.redirect_chain, start=1):
            sec_icon = "✅" if hop.is_https else "❌"
            lines.append(f"| {idx} | `{hop.url}` | {hop.status_code} | {sec_icon} |")
        lines.append("")
    else:
        lines.append("> ℹ️ No redirections occurred.\n")

    # CSP bypass warnings section
    if report.csp_bypass_warnings:
        lines.append("---\n")
        lines.append("## ⚠️ CSP Bypass Analysis\n")
        for warning in report.csp_bypass_warnings:
            lines.append(f"- ⚠️ {warning}")
        lines.append("")

    # Smart Fuzzing section
    lines.append("---\n")
    lines.append("## 📂 Smart Path Fuzzing Exposure Analysis\n")
    if report.fuzz_findings:
        lines.append("| Scanned Path | Status | Exposure Status | Severity | Description |")
        lines.append("| --- | :---: | :---: | :---: | --- |")
        for fuzz in report.fuzz_findings:
            status = "🔴 EXPOSED" if fuzz.is_exposed else "🟢 SECURE"
            lines.append(f"| `{fuzz.path}` | {fuzz.status_code} | **{status}** | `{fuzz.severity}` | {fuzz.description} |")
        lines.append("")
    else:
        lines.append("> 🟢 No sensitive configuration or exposure files discovered during fuzzer scanning.\n")

    # Information leakage
    lines.append("---\n")
    lines.append("## 🔍 Information Leakage\n")

    if report.leakage_findings:
        lines.append(f"> ⚠️ **{len(report.leakage_findings)}** header(s) expose server technology or version information.\n")
        lines.append("| Header | Exposed Value | Severity |")
        lines.append("| --- | --- | :---: |")

        severity_icons = {"High": "🔴", "Medium": "🟡", "Low": "⚪"}

        for leak in report.leakage_findings:
            icon = severity_icons.get(leak.severity, "⚪")
            value_display = f"`{leak.value[:50]}…`" if len(leak.value) > 50 else f"`{leak.value}`"
            lines.append(f"| **{leak.header_name}** | {value_display} | {icon} {leak.severity} |")

        lines.append("")

        # Remediation details.
        lines.append("### Remediation\n")
        for leak in report.leakage_findings:
            lines.append(f"**`{leak.header_name}`**: {leak.recommendation}\n")
    else:
        lines.append("> ✅ No server information leakage detected.\n")

    # SSL information
    lines.append("---\n")
    lines.append("## 🔒 SSL/TLS Certificate Information\n")

    if report.ssl_info and not report.ssl_info.error:
        ssl = report.ssl_info
        cert_status = "✅ Valid" if ssl.is_valid else "❌ Expired / Invalid"
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| **Status** | {cert_status} |")
        lines.append(f"| **Issuer** | {ssl.issuer} |")
        lines.append(f"| **Subject** | {ssl.subject} |")
        lines.append(f"| **Valid From** | {_format_date(ssl.not_before)} |")
        lines.append(f"| **Valid Until** | {_format_date(ssl.not_after)} |")
        lines.append(f"| **Days Remaining** | {ssl.days_remaining} |")
        lines.append(f"| **Serial Number** | `{ssl.serial_number}` |")
        lines.append("")

        lines.append("### Active SSL/TLS Protocol Support\n")
        lines.append("| Protocol Version | Support Status |")
        lines.append("| --- | --- |")
        for v in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]:
            status = "✅ Supported" if v in ssl.supported_tls_versions else ("❌ Rejected" if v in ssl.rejected_tls_versions else "➖ Untested (Local client limitation)")
            lines.append(f"| **{v}** | {status} |")
        lines.append("")

        lines.append("### Legacy Weak Ciphers Test Matrix\n")
        lines.append("| Cipher Suite | Security Status |")
        lines.append("| --- | --- |")
        for wc in ["RC4", "3DES", "aNULL", "eNULL", "EXPORT"]:
            is_supported = wc in ssl.supported_weak_ciphers
            status = "❌ VULNERABLE (Supported)" if is_supported else "✅ SECURE (Rejected)"
            lines.append(f"| **{wc}** | {status} |")
        lines.append("")
    elif report.ssl_info and report.ssl_info.error:
        lines.append(f"> ⚠️ **SSL Error:** {report.ssl_info.error}\n")
    else:
        lines.append("> ℹ️ SSL information was not retrieved for this target.\n")

    # Recommendations
    if report.recommendations:
        lines.append("---\n")
        lines.append("## 💡 Recommendations\n")
        for idx, rec in enumerate(report.recommendations, start=1):
            lines.append(f"{idx}. {rec}")
        lines.append("")

    # Footer
    lines.append("---\n")
    lines.append("*Report generated by [WebArmor-Audit](https://github.com/webarmor/webarmor-audit) — HTTP Security Headers Auditor.*\n")

    content = "\n".join(lines)

    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return content


def generate_json_bulk_summary(reports: List[AuditReport], output_path: str) -> None:
    """Render a bulk audit summary as a structured JSON file."""
    from urllib.parse import urlparse
    
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    results = []
    for r in reports:
        parsed_url = urlparse(r.url)
        host_sanitized = parsed_url.hostname.replace(".", "_") if parsed_url.hostname else "target"
        base, ext = os.path.splitext(output_path)
        file_ref = f"{os.path.basename(base)}_{host_sanitized}{ext}"
        results.append({
            "url": r.url,
            "grade": r.grade,
            "score": r.total_score,
            "max_score": r.max_score,
            "percentage": r.score_percentage,
            "ip_address": r.ip_address,
            "status_code": r.status_code,
            "report_file": file_ref
        })
        
    summary_data = {
        "generated_at": now,
        "total_targets": len(reports),
        "results": results
    }
    
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2, ensure_ascii=False)


def generate_html_bulk_summary(reports: List[AuditReport], output_path: str) -> None:
    """Render a bulk audit summary as a premium responsive dark-neon HTML dashboard."""
    from urllib.parse import urlparse
    
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    total_targets = len(reports)
    avg_score = round(sum(r.score_percentage for r in reports) / total_targets, 1) if total_targets > 0 else 0.0
    
    grades_dist = {}
    for r in reports:
        grades_dist[r.grade] = grades_dist.get(r.grade, 0) + 1
        
    grade_distribution_badges = "".join(
        f"<span class='badge info'>{grade}: {count}</span> " for grade, count in sorted(grades_dist.items())
    )
    
    table_rows = []
    accent_colors = {
        "A+": "#10b981", "A": "#059669",
        "B": "#fbbf24", "C": "#f59e0b",
        "D": "#ef4444", "F": "#dc2626"
    }
    
    for r in reports:
        parsed_url = urlparse(r.url)
        host_sanitized = parsed_url.hostname.replace(".", "_") if parsed_url.hostname else "target"
        base, ext = os.path.splitext(output_path)
        file_ref = f"{os.path.basename(base)}_{host_sanitized}{ext}"
        
        grade_color = accent_colors.get(r.grade, "#3b82f6")
        
        table_rows.append(f"""
        <tr>
            <td><strong><a href='{r.url}' target='_blank' style='color: #60a5fa; text-decoration: none;'>{r.url}</a></strong></td>
            <td><span class='badge' style='background: {grade_color}22; color: {grade_color}; border: 1px solid {grade_color}44;'>{r.grade}</span></td>
            <td>{r.total_score}/{r.max_score}</td>
            <td><strong>{r.score_percentage}%</strong></td>
            <td><code>{r.ip_address}</code></td>
            <td>{r.status_code}</td>
            <td><a href='{file_ref}' class='badge info' style='text-decoration: none;'>View Report ➔</a></td>
        </tr>
        """)
        
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebArmor-Audit — Bulk Scan Summary</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #3b82f6;
            --pass-color: #10b981;
            --warn-color: #f59e0b;
            --fail-color: #ef4444;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        
        header {{
            margin-bottom: 40px;
            text-align: center;
        }}
        
        h1 {{
            font-weight: 700;
            font-size: 2.5rem;
            margin-bottom: 10px;
            letter-spacing: -1px;
            color: #fff;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-top: 30px;
            margin-bottom: 40px;
        }}
        
        .meta-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 20px;
            border-radius: 16px;
            text-align: center;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        }}
        
        .meta-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        
        .meta-value {{
            font-weight: 700;
            font-size: 1.5rem;
            color: #fff;
        }}
        
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
        }}
        
        h3 {{
            margin-bottom: 20px;
            color: #fff;
            font-weight: 600;
        }}
        
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95rem;
        }}
        
        .report-table th, .report-table td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .report-table th {{
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-align: center;
        }}
        
        .badge.info {{ background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        
        code {{
            font-family: monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 4px;
            color: #f472b6;
        }}
        
        footer {{
            text-align: center;
            margin-top: 60px;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
        
        footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ WebArmor-Audit Summary</h1>
            <p style="color: var(--text-muted);">Bulk Scanning Results Dashboard</p>
        </header>
        
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-title">Total Targets</div>
                <div class="meta-value">{total_targets}</div>
            </div>
            <div class="meta-card">
                <div class="meta-title">Average Score</div>
                <div class="meta-value" style="color: var(--pass-color);">{avg_score}%</div>
            </div>
            <div class="meta-card">
                <div class="meta-title">Grades Distribution</div>
                <div style="margin-top: 5px;">{grade_distribution_badges}</div>
            </div>
            <div class="meta-card">
                <div class="meta-title">Scan Date</div>
                <div class="meta-value" style="font-size: 1.1rem; font-weight: 400; margin-top: 5px;">{now}</div>
            </div>
        </div>
        
        <div class="card">
            <h3>📊 Audited Targets Summary</h3>
            <table class="report-table">
                <thead>
                    <tr>
                        <th>Target URL</th>
                        <th>Grade</th>
                        <th>Score</th>
                        <th>Percentage</th>
                        <th>Resolved IP</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(table_rows)}
                </tbody>
            </table>
        </div>
        
        <footer>
            Report generated by <a href="https://github.com/webarmor/webarmor-audit" target="_blank">WebArmor-Audit</a> — Security Auditor.
        </footer>
    </div>
</body>
</html>
"""
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(html_content)
