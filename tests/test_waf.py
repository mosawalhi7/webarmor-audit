from webarmor_audit.waf import detect_waf


def test_detect_waf_none():
    """Test detect_waf when no firewalls are present."""
    headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41 (Ubuntu)"
    }
    cookies = ["session_id=123"]
    waf = detect_waf(headers, cookies)
    assert waf.detected is False
    assert waf.waf_name == "None"


def test_detect_waf_cloudflare_header():
    """Test detect_waf triggers on Cloudflare CF-Ray header."""
    headers = {
        "CF-Ray": "885728a8d11c7c94-AMS",
        "Server": "cloudflare"
    }
    waf = detect_waf(headers, [])
    assert waf.detected is True
    assert waf.waf_name == "Cloudflare"
    assert "CF-Ray" in waf.reason


def test_detect_waf_cloudflare_cookie():
    """Test detect_waf triggers on Cloudflare __cfduid tracking cookie."""
    cookies = ["__cfduid=d3129849204cba7; Path=/"]
    waf = detect_waf({}, cookies)
    assert waf.detected is True
    assert waf.waf_name == "Cloudflare"


def test_detect_waf_aws():
    """Test detect_waf triggers on AWS WAF load balancer cookies."""
    cookies = ["AWSALB=secret_routing_token; Path=/"]
    waf = detect_waf({}, cookies)
    assert waf.detected is True
    assert waf.waf_name == "AWS WAF / Elastic Load Balancer"


def test_detect_waf_akamai():
    """Test detect_waf triggers on Akamai headers."""
    headers = {
        "X-Akamai-Transformed": "9 1643 0 pmb=mRUM,1",
    }
    waf = detect_waf(headers, [])
    assert waf.detected is True
    assert waf.waf_name == "Akamai WAF"


def test_detect_waf_imperva():
    """Test detect_waf triggers on Imperva session cookies."""
    cookies = ["visid_incap_2299388=session_id; Path=/"]
    waf = detect_waf({}, cookies)
    assert waf.detected is True
    assert waf.waf_name == "Imperva Incapsula WAF"


def test_detect_waf_modsecurity():
    """Test detect_waf triggers on ModSecurity Server header."""
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu) ModSecurity/2.9.3"
    }
    waf = detect_waf(headers, [])
    assert waf.detected is True
    assert waf.waf_name == "ModSecurity WAF"


def test_detect_waf_fortiweb():
    """Test detect_waf triggers on FortiWeb cookies."""
    cookies = ["fortiwafsid=session_token"]
    waf = detect_waf({}, cookies)
    assert waf.detected is True
    assert waf.waf_name == "Fortinet FortiWeb WAF"


def test_detect_waf_f5_big_ip():
    """Test detect_waf triggers on F5 BIG-IP ASM cookies."""
    cookies = ["TS012345=token_value"]
    waf = detect_waf({}, cookies)
    assert waf.detected is True
    assert waf.waf_name == "F5 BIG-IP ASM WAF"
