import socket
import pytest
from unittest.mock import patch

from webarmor_audit.headers import validate_url, analyse_headers
from webarmor_audit.exceptions import InvalidURLError


def test_validate_url_success():
    """Test validate_url normalizes URLs and runs DNS lookup check successfully."""
    # Mock socket.getaddrinfo to simulate successful DNS resolution
    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        
        # Test normal URLs
        assert validate_url("example.com") == "https://example.com"
        assert validate_url("http://testsite.org") == "http://testsite.org"
        assert validate_url("https://sub.domain.local/path") == "https://sub.domain.local/path"
        
        mock_getaddrinfo.assert_called()


def test_validate_url_failures():
    """Test validate_url raises correct exceptions on empty or unresolving domains."""
    with pytest.raises(InvalidURLError, match="URL cannot be empty"):
        validate_url("")
        
    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        # Simulate DNS resolution failure
        mock_getaddrinfo.side_effect = socket.gaierror("getaddrinfo failed")
        
        with pytest.raises(InvalidURLError, match="does not resolve"):
            validate_url("thisdomainnamedoesnotexist12345.com")


def test_analyse_headers_missing():
    """Test header analysis scoring when all headers are missing."""
    results = analyse_headers({})
    assert len(results) == 6
    for r in results:
        assert r.present is False
        assert r.score == 0
        assert "Add" in r.recommendation or "missing" in r.recommendation.lower()


def test_analyse_headers_perfect_scores():
    """Test header analysis scores when all headers are perfectly configured."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
    }
    results = analyse_headers(headers)
    assert len(results) == 6
    for r in results:
        assert r.present is True
        assert r.is_valid is True
        assert r.score == r.max_score
        assert r.recommendation == ""


def test_analyse_headers_partial_scores():
    """Test header analysis scores with partial configurations and warnings."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "Strict-Transport-Security": "max-age=1500",  # HSTS max-age too small
        "X-Frame-Options": "INVALID_OPTION",
        "Referrer-Policy": "unsafe-url"
    }
    results = analyse_headers(headers)
    
    csp = [r for r in results if r.name == "Content-Security-Policy"][0]
    assert csp.present is True
    # CSP is present but score is deducted because of 'unsafe-inline'
    assert csp.score < csp.max_score
    assert "unsafe-inline" in csp.recommendation

    hsts = [r for r in results if r.name == "Strict-Transport-Security"][0]
    assert hsts.present is True
    assert hsts.score < hsts.max_score
    assert "max-age" in hsts.recommendation
    assert "includeSubDomains" in hsts.recommendation

    xfo = [r for r in results if r.name == "X-Frame-Options"][0]
    assert xfo.present is True
    assert xfo.score == xfo.max_score // 2
    assert "not a recommended value" in xfo.recommendation
