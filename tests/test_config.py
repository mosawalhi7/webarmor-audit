import os
import tempfile
import pytest
from webarmor_audit.config import parse_simple_toml, load_config, apply_profile
from webarmor_audit.constants import SECURITY_HEADERS, GRADE_THRESHOLDS


def test_parse_simple_toml():
    """Test custom fallback TOML parser logic."""
    toml_str = """
    # Comments should be ignored
    title = "WebArmor Test Profile"
    
    [headers]
    Content-Security-Policy = 30
    X-XSS-Protection = 5
    
    [thresholds]
    "A+" = 95
    A = 85
    F = 0
    """
    config = parse_simple_toml(toml_str)
    assert config["title"] == "WebArmor Test Profile"
    assert config["headers"]["Content-Security-Policy"] == 30
    assert config["headers"]["X-XSS-Protection"] == 5
    assert config["thresholds"]["A+"] == 95
    assert config["thresholds"]["A"] == 85
    assert config["thresholds"]["F"] == 0


def test_load_config_non_existent():
    """Test load_config raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        load_config("this_file_does_not_exist_12345.toml")


def test_load_config_success():
    """Test load_config successfully parses a file on disk."""
    toml_str = """
    [headers]
    Content-Security-Policy = 25
    """
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".toml") as tmp:
        tmp.write(toml_str)
        tmp_path = tmp.name

    try:
        config = load_config(tmp_path)
        assert config["headers"]["Content-Security-Policy"] == 25
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_apply_profile():
    """Test apply_profile overrides security headers and grade thresholds."""
    # Backup original constants to avoid test pollution
    orig_headers = {k: dict(v) for k, v in SECURITY_HEADERS.items()}
    orig_thresholds = list(GRADE_THRESHOLDS)

    mock_profile = {
        "headers": {
            "Content-Security-Policy": 45,      # Modify existing header weight
            "X-My-Custom-Header": 10            # Add custom header
        },
        "thresholds": {
            "A+": 98,
            "F": 5
        }
    }

    try:
        apply_profile(mock_profile)
        
        # Check modified header weight
        assert SECURITY_HEADERS["Content-Security-Policy"]["weight"] == 45
        
        # Check newly registered custom header
        assert "X-My-Custom-Header" in SECURITY_HEADERS
        assert SECURITY_HEADERS["X-My-Custom-Header"]["weight"] == 10
        assert "Custom tracked header" in SECURITY_HEADERS["X-My-Custom-Header"]["description"]
        
        # Check overridden grade thresholds
        assert len(GRADE_THRESHOLDS) == 2
        # Verify ordering (A+ with 98 first, F with 5 second)
        assert GRADE_THRESHOLDS[0] == (98, "A+")
        assert GRADE_THRESHOLDS[1] == (5, "F")
        
    finally:
        # Restore original constants
        SECURITY_HEADERS.clear()
        SECURITY_HEADERS.update(orig_headers)
        GRADE_THRESHOLDS.clear()
        GRADE_THRESHOLDS.extend(orig_thresholds)
