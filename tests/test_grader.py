import pytest
from webarmor_audit.grader import compute_score, assign_grade, collect_recommendations
from webarmor_audit.models import HeaderResult, SSLInfo, CookieFinding, FuzzFinding, AuditReport


def test_compute_score(sample_header_results):
    """Test that compute_score correctly sums score and max_score fields."""
    total, maximum = compute_score(sample_header_results)
    assert total == 20
    assert maximum == 40


@pytest.mark.parametrize(
    "score, max_score, expected_grade",
    [
        (98, 100, "A+"),
        (95, 100, "A+"),
        (90, 100, "A"),
        (85, 100, "A"),
        (80, 100, "B"),
        (70, 100, "B"),
        (65, 100, "C"),
        (55, 100, "C"),
        (50, 100, "D"),
        (40, 100, "D"),
        (30, 100, "F"),
        (0, 100, "F"),
        (0, 0, "F"),
    ]
)
def test_assign_grade(score, max_score, expected_grade):
    """Test assign_grade mapping percentages to correct letter grades."""
    assert assign_grade(score, max_score) == expected_grade


def test_collect_recommendations(sample_audit_report):
    """Test collection of header, cookie, SSL, WAF and fuzzer recommendations."""
    recs = collect_recommendations(sample_audit_report)
    
    # 1. Header recommendations
    header_rec = [r for r in recs if "[Strict-Transport-Security]" in r]
    assert len(header_rec) == 1
    # Check for CWE & OWASP mapping addition in header recommendations
    assert "CWE-523" in header_rec[0]
    assert "A05:2021-Security Misconfiguration" in header_rec[0]

    # 2. Cookie recommendations
    cookie_recs = [r for r in recs if "[Cookie Security]" in r]
    assert len(cookie_recs) == 3
    assert any("Add 'Secure' flag to: tracking_id" in r for r in cookie_recs)
    assert any("Add 'HttpOnly' flag to: tracking_id" in r for r in cookie_recs)
    assert any("Add 'SameSite' attribute to: tracking_id" in r for r in cookie_recs)
    
    # Check that cookie recommendations carry the CWE/OWASP suffix
    assert any("CWE-614" in r for r in cookie_recs)

    # 3. SSL recommendations
    # Add a mock SSL with deprecated protocols and weak ciphers to test
    sample_audit_report.ssl_info.has_tls10_or_below = True
    sample_audit_report.ssl_info.has_weak_ciphers = True
    sample_audit_report.ssl_info.supported_weak_ciphers = ["RC4", "3DES"]
    
    ssl_recs = collect_recommendations(sample_audit_report)
    assert any("[SSL/TLS Protocol]" in r for r in ssl_recs)
    assert any("[SSL/TLS Ciphers]" in r for r in ssl_recs)
    
    # 4. Fuzzer exposure recommendations
    sample_audit_report.fuzz_findings = [
        FuzzFinding(
            path="/.env",
            status_code=200,
            is_exposed=True,
            severity="High",
            description="Env backup",
            remediation="Secure path"
        ),
        FuzzFinding(
            path="/.git/HEAD",
            status_code=200,
            is_exposed=False,
            severity="High",
            description="Git HEAD",
            remediation="Secure HEAD"
        )
    ]
    fuzz_recs = collect_recommendations(sample_audit_report)
    exposed_recs = [r for r in fuzz_recs if "[Sensitive Exposure]" in r]
    assert len(exposed_recs) == 1
    assert "path '/.env'" in exposed_recs[0]
    assert "CWE-200" in exposed_recs[0]
