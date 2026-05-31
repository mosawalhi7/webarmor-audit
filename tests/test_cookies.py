from webarmor_audit.cookies import analyse_cookies


def test_analyse_cookies_no_cookies():
    """Test cookie analyzer returns empty list when no cookies are set."""
    assert analyse_cookies([], is_https=True) == []


def test_analyse_cookies_fully_secure():
    """Test cookie analyzer identifies fully secure and protected cookies."""
    cookie_headers = [
        "session=secret_token; Path=/; Secure; HttpOnly; SameSite=Strict",
        "preferences=dark; Path=/; Secure; HttpOnly; SameSite=Lax"
    ]
    findings = analyse_cookies(cookie_headers, is_https=True)
    assert len(findings) == 2
    
    session = [f for f in findings if f.name == "session"][0]
    assert session.has_secure is True
    assert session.has_httponly is True
    assert session.has_samesite is True
    assert session.samesite_value == "Strict"
    assert session.issue_count == 0
    assert session.is_fully_protected is True

    pref = [f for f in findings if f.name == "preferences"][0]
    assert pref.has_secure is True
    assert pref.has_httponly is True
    assert pref.has_samesite is True
    assert pref.samesite_value == "Lax"
    assert pref.issue_count == 0
    assert pref.is_fully_protected is True


def test_analyse_cookies_missing_flags():
    """Test cookie analyzer flags missing HttpOnly, Secure, and SameSite fields."""
    cookie_headers = [
        "insecure_cookie=val; Path=/",
        "half_secure_cookie=val; Path=/; HttpOnly; SameSite=None"
    ]
    # Under HTTPS connection
    findings = analyse_cookies(cookie_headers, is_https=True)
    assert len(findings) == 2

    c1 = [f for f in findings if f.name == "insecure_cookie"][0]
    assert c1.has_secure is False
    assert c1.has_httponly is False
    assert c1.has_samesite is False
    assert c1.issue_count == 3
    assert any("HttpOnly" in issue for issue in c1.issues)
    assert any("Secure" in issue for issue in c1.issues)
    assert any("SameSite" in issue for issue in c1.issues)
    assert c1.is_fully_protected is False

    c2 = [f for f in findings if f.name == "half_secure_cookie"][0]
    assert c2.has_secure is False
    assert c2.has_httponly is True
    assert c2.has_samesite is True
    assert c2.samesite_value == "None"
    assert c2.issue_count == 2
    assert any("Secure" in issue for issue in c2.issues)
    assert any("SameSite=None requires" in issue for issue in c2.issues)
    assert c2.is_fully_protected is False


def test_analyse_cookies_http_connection():
    """Test cookie analyzer behaves correctly on HTTP (non-secure) connections."""
    cookie_headers = [
        "mycookie=val; Path=/; Secure; HttpOnly; SameSite=Strict"
    ]
    # Under HTTP connection
    findings = analyse_cookies(cookie_headers, is_https=False)
    assert len(findings) == 1
    
    c = findings[0]
    assert c.has_secure is True
    assert c.has_httponly is True
    assert c.has_samesite is True
    assert c.issue_count == 1
    assert "Secure flag set on insecure HTTP connection" in c.issues
    assert c.is_fully_protected is False
