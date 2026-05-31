"""
Data models for WebArmor-Audit.

Uses Python dataclasses to define clean, typed structures for header
analysis results, SSL certificate info, cookie security findings,
server information leakage, and the overall audit report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class HeaderResult:
    """Analysis result for a single HTTP security header."""

    name: str
    present: bool
    value: Optional[str] = None
    is_valid: bool = False
    score: int = 0
    max_score: int = 0
    recommendation: str = ""
    description: str = ""


@dataclass
class SSLInfo:
    """Basic SSL/TLS certificate information."""

    issuer: str = "N/A"
    subject: str = "N/A"
    serial_number: str = "N/A"
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: int = -1
    version: int = 0
    is_valid: bool = False
    error: Optional[str] = None
    supported_tls_versions: List[str] = field(default_factory=list)
    rejected_tls_versions: List[str] = field(default_factory=list)
    supported_weak_ciphers: List[str] = field(default_factory=list)
    has_tls10_or_below: bool = False
    has_weak_ciphers: bool = False



@dataclass
class CookieFinding:
    """Security analysis result for a single HTTP cookie."""

    name: str
    has_secure: bool = False
    has_httponly: bool = False
    has_samesite: bool = False
    samesite_value: str = ""
    has_secure_prefix: bool = False
    path: str = ""
    domain: str = ""
    is_session: bool = False
    raw_value: str = ""
    issues: List[str] = field(default_factory=list)

    @property
    def is_fully_protected(self) -> bool:
        """Return True if all critical security flags are set and no issues are detected."""
        return self.has_secure and self.has_httponly and self.has_samesite and not self.issues

    @property
    def issue_count(self) -> int:
        """Return the number of security issues found."""
        return len(self.issues)


@dataclass
class LeakageInfo:
    """A single instance of server information leakage via HTTP headers."""

    header_name: str
    value: str
    severity: str = "Medium"
    recommendation: str = ""


@dataclass
class CORSEvaluation:
    """CORS header security evaluation."""

    header_name: str
    value: str
    is_secure: bool
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class FuzzFinding:
    """Audit result for a single scanned path."""

    path: str
    status_code: int
    is_exposed: bool
    severity: str
    description: str
    remediation: str


@dataclass
class WAFDetails:
    """Web Application Firewall detection details."""

    detected: bool
    waf_name: str
    reason: str
    signature_type: str  # "Cookie" or "Header"


@dataclass
class SecurityTxtFinding:
    """Audit result for the security.txt file presence and compliance."""

    present: bool
    url_checked: str
    status_code: int = 0
    has_contact: bool = False
    has_expires: bool = False
    is_expired: bool = False
    expires_date: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class RedirectHop:
    """A single hop in the HTTP redirect chain."""

    url: str
    status_code: int
    is_https: bool
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuditReport:
    """Complete audit report combining header analysis and SSL info."""

    url: str
    timestamp: str = ""
    ip_address: str = "N/A"
    server: str = "N/A"
    status_code: int = 0
    headers: List[HeaderResult] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    total_score: int = 0
    max_score: int = 100
    grade: str = "F"
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    cookie_findings: List[CookieFinding] = field(default_factory=list)
    leakage_findings: List[LeakageInfo] = field(default_factory=list)
    
    # New audit fields (v1.2.0)
    cors_findings: List[CORSEvaluation] = field(default_factory=list)
    security_txt_finding: Optional[SecurityTxtFinding] = None
    supported_protocols: List[str] = field(default_factory=list)
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    csp_bypass_warnings: List[str] = field(default_factory=list)

    # Phase 9 fields
    fuzz_findings: List[FuzzFinding] = field(default_factory=list)
    waf_details: Optional[WAFDetails] = None

    @property
    def score_percentage(self) -> float:
        """Return the score as a percentage (0.0–100.0)."""
        if self.max_score == 0:
            return 0.0
        return round((self.total_score / self.max_score) * 100, 1)

