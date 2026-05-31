import pytest
from unittest.mock import patch, MagicMock
import requests

from webarmor_audit.fuzzer import run_smart_fuzz, _fuzz_single_path


def test_fuzz_single_path_not_exposed():
    """Test that _fuzz_single_path returns None when the path is not exposed."""
    item = {
        "path": "/.env",
        "severity": "High",
        "description": "Env backup",
        "remediation": "Secure path",
        "keyword": "DB_"
    }
    
    with patch("requests.get") as mock_get:
        # Simulate a 404 Not Found
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = _fuzz_single_path("https://test.com/", item, timeout=5, verify_ssl=True)
        assert result is None


def test_fuzz_single_path_exposed():
    """Test that _fuzz_single_path returns FuzzFinding when the path is exposed and keyword matches."""
    item = {
        "path": "/.env",
        "severity": "High",
        "description": "Env backup",
        "remediation": "Secure path",
        "keyword": "DB_"
    }
    
    with patch("requests.get") as mock_get:
        # Simulate a 200 OK containing the signature keyword
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"DB_HOST=127.0.0.1\nDB_PASSWORD=secret"
        mock_get.return_value = mock_response
        
        result = _fuzz_single_path("https://test.com/", item, timeout=5, verify_ssl=True)
        assert result is not None
        assert result.path == "/.env"
        assert result.is_exposed is True
        assert result.status_code == 200
        assert result.severity == "High"


def test_fuzz_single_path_false_positive():
    """Test that _fuzz_single_path filters out false positive custom 200 OK HTML pages."""
    item = {
        "path": "/.env",
        "severity": "High",
        "description": "Env backup",
        "remediation": "Secure path",
        "keyword": "DB_"
    }
    
    with patch("requests.get") as mock_get:
        # Simulate a 200 OK but returning standard login HTML (no keyword)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body>Welcome to the login page</body></html>"
        mock_get.return_value = mock_response
        
        result = _fuzz_single_path("https://test.com/", item, timeout=5, verify_ssl=True)
        assert result is None


def test_fuzz_single_path_exceptions():
    """Test that _fuzz_single_path handles request exceptions gracefully."""
    item = {
        "path": "/.env",
        "severity": "High",
        "description": "Env backup",
        "remediation": "Secure path",
        "keyword": "DB_"
    }
    
    with patch("requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Connection failed")
        
        result = _fuzz_single_path("https://test.com/", item, timeout=5, verify_ssl=True)
        assert result is None


@patch("webarmor_audit.fuzzer._fuzz_single_path")
def test_run_smart_fuzz_aggregation(mock_fuzz):
    """Test run_smart_fuzz correctly aggregates fuzzer findings from threads."""
    from webarmor_audit.models import FuzzFinding
    
    # Mock fuzz findings returned by thread workers
    mock_fuzz.side_effect = lambda base_url, item, timeout, verify_ssl: (
        FuzzFinding(
            path=item["path"],
            status_code=200,
            is_exposed=True,
            severity=item["severity"],
            description=item["description"],
            remediation=item["remediation"]
        ) if item["path"] in ["/.env", "/.git/HEAD"] else None
    )
    
    findings = run_smart_fuzz("https://test.com", timeout=5, verify_ssl=True)
    
    # We should have exactly 2 exposed findings
    assert len(findings) == 2
    paths = [f.path for f in findings]
    assert "/.env" in paths
    assert "/.git/HEAD" in paths
    
    # Ensure they are sorted by severity High first
    assert findings[0].severity == "High"
