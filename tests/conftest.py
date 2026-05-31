import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from datetime import datetime, timezone
from webarmor_audit.models import AuditReport, HeaderResult, SSLInfo, CookieFinding, WAFDetails


@pytest.fixture
def sample_header_results():
    """Return a list of sample security header evaluation results."""
    return [
        HeaderResult(
            name="Content-Security-Policy",
            present=True,
            value="default-src 'self'",
            is_valid=True,
            score=20,
            max_score=20,
            recommendation="",
            description="Controls resource loading"
        ),
        HeaderResult(
            name="Strict-Transport-Security",
            present=False,
            value=None,
            is_valid=False,
            score=0,
            max_score=20,
            recommendation="Add Strict-Transport-Security",
            description="Enforces HTTPS"
        )
    ]


@pytest.fixture
def sample_audit_report(sample_header_results):
    """Return a fully populated AuditReport instance for testing."""
    ssl_info = SSLInfo(
        issuer="CN=Test Issuer",
        subject="CN=test.com",
        serial_number="12345",
        not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2026, 1, 1, tzinfo=timezone.utc),
        days_remaining=300,
        version=3,
        is_valid=True,
        supported_tls_versions=["TLSv1.3", "TLSv1.2"],
        rejected_tls_versions=["TLSv1.1", "TLSv1.0", "SSLv3"],
        supported_weak_ciphers=[],
        has_tls10_or_below=False,
        has_weak_ciphers=False
    )
    
    waf_details = WAFDetails(
        detected=True,
        waf_name="Cloudflare",
        reason="Server header detected",
        signature_type="Header"
    )

    cookie_findings = [
        CookieFinding(
            name="session_id",
            has_secure=True,
            has_httponly=True,
            has_samesite=True,
            samesite_value="Strict",
            issues=[]
        ),
        CookieFinding(
            name="tracking_id",
            has_secure=False,
            has_httponly=False,
            has_samesite=False,
            samesite_value="",
            issues=["Missing HttpOnly flag", "Missing Secure flag", "Missing SameSite attribute"]
        )
    ]

    return AuditReport(
        url="https://test.com",
        timestamp="2026-05-30 20:00:00 UTC",
        ip_address="127.0.0.1",
        server="cloudflare",
        status_code=200,
        headers=sample_header_results,
        ssl_info=ssl_info,
        total_score=20,
        max_score=40,
        grade="F",
        summary="Weak posture",
        recommendations=["[Strict-Transport-Security] Add Strict-Transport-Security"],
        cookie_findings=cookie_findings,
        waf_details=waf_details
    )
