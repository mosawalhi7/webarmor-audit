"""
Constants and configuration values for WebArmor-Audit.

Centralizes all security header definitions, scoring weights, grade
thresholds, and default configuration to keep the rest of the codebase
clean and easily tunable.
"""

from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# HTTP Security Headers — canonical names and analysis metadata
# ---------------------------------------------------------------------------

# Each entry maps the header name to a dict describing:
#   - weight:      points awarded when the header is present and valid
#   - description: short human-readable purpose
#   - recommended: example of a strong configuration
#   - directives:  (optional) critical directives to look for in the value

SECURITY_HEADERS: Dict[str, dict] = {
    "Content-Security-Policy": {
        "weight": 20,
        "description": (
            "Controls which resources the browser is allowed to load. "
            "Mitigates XSS, data injection, and clickjacking attacks."
        ),
        "recommended": "default-src 'self'; script-src 'self'; style-src 'self'",
        "directives": ["default-src", "script-src"],
    },
    "Strict-Transport-Security": {
        "weight": 20,
        "description": (
            "Enforces HTTPS connections and prevents protocol downgrade "
            "attacks and cookie hijacking."
        ),
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "directives": ["max-age"],
    },
    "X-Frame-Options": {
        "weight": 15,
        "description": (
            "Prevents the page from being embedded in iframes, "
            "mitigating clickjacking attacks."
        ),
        "recommended": "DENY",
        "valid_values": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "description": (
            "Prevents MIME-type sniffing, forcing the browser to "
            "respect the declared Content-Type."
        ),
        "recommended": "nosniff",
        "valid_values": ["nosniff"],
    },
    "Referrer-Policy": {
        "weight": 15,
        "description": (
            "Controls how much referrer information is sent with "
            "requests, protecting user privacy."
        ),
        "recommended": "strict-origin-when-cross-origin",
        "valid_values": [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
    },
    "Permissions-Policy": {
        "weight": 15,
        "description": (
            "Restricts browser features (camera, microphone, geolocation, etc.) "
            "to reduce the attack surface."
        ),
        "recommended": "geolocation=(), camera=(), microphone=()",
        "directives": ["geolocation", "camera", "microphone"],
    },
}

# ---------------------------------------------------------------------------
# Grading thresholds — maps minimum score to letter grade
# ---------------------------------------------------------------------------

# Evaluated top-down; the first threshold the score meets determines the grade.
GRADE_THRESHOLDS: List[Tuple[int, str]] = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
]

# ---------------------------------------------------------------------------
# Network defaults
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 15  # seconds
DEFAULT_PORT: int = 443
USER_AGENT: str = (
    "WebArmor-Audit/1.0 "
    "(Security Header Scanner; +https://github.com/webarmor/webarmor-audit)"
)

# ---------------------------------------------------------------------------
# Report defaults
# ---------------------------------------------------------------------------

DEFAULT_REPORT_FILENAME: str = "audit_report.md"

# ---------------------------------------------------------------------------
# CWE & OWASP Standards Mapping
# ---------------------------------------------------------------------------
CWE_OWASP_MAPPING: Dict[str, Dict[str, str]] = {
    "Content-Security-Policy": {
        "cwe": "CWE-1021",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "Strict-Transport-Security": {
        "cwe": "CWE-523",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "X-Frame-Options": {
        "cwe": "CWE-1021",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "X-Content-Type-Options": {
        "cwe": "CWE-116",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "Referrer-Policy": {
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control"
    },
    "Permissions-Policy": {
        "cwe": "CWE-276",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "Cookie Security": {
        "cwe": "CWE-614",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "Information Leakage": {
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control"
    },
    "CORS Audit": {
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "SSL/TLS Config": {
        "cwe": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures"
    },
    "CSP Bypass": {
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection"
    },
    "Redirect Chain": {
        "cwe": "CWE-601",
        "owasp": "A01:2021-Broken Access Control"
    }
}

# ---------------------------------------------------------------------------
# Smart Fuzzing target paths & validation rules
# ---------------------------------------------------------------------------
FUZZ_PATHS: List[Dict[str, str]] = [
    {
        "path": "/.env",
        "severity": "High",
        "description": "Environment configuration files often contain exposed API keys, secret credentials, or database passwords.",
        "remediation": "Configure webserver directives to block all access to files starting with dot (.) or restrict it.",
        "keyword": "DB_"
    },
    {
        "path": "/.git/HEAD",
        "severity": "High",
        "description": "Exposed Git repository directory allows attackers to download complete source code of the web application.",
        "remediation": "Block access to .git folders via webserver rewrite rules or configuration policies.",
        "keyword": "ref:"
    },
    {
        "path": "/.git/config",
        "severity": "High",
        "description": "Exposed Git config file revealing internal paths, repository locations, and sometimes credentials.",
        "remediation": "Deny public access to .git and related directories.",
        "keyword": "repositoryformatversion"
    },
    {
        "path": "/wp-config.php.bak",
        "severity": "High",
        "description": "WordPress backup configuration contains active DB usernames, host coordinates, and passwords.",
        "remediation": "Delete backup configurations from the public web server directory.",
        "keyword": "DB_PASSWORD"
    },
    {
        "path": "/wp-config.php.old",
        "severity": "High",
        "description": "WordPress backup config file containing active DB parameters.",
        "remediation": "Remove old configuration files from target folders.",
        "keyword": "DB_USER"
    },
    {
        "path": "/config.php.bak",
        "severity": "High",
        "description": "Generic PHP configuration backup containing sensitive site setup variables.",
        "remediation": "Delete backup config scripts from public server folders.",
        "keyword": "<?php"
    },
    {
        "path": "/config.json",
        "severity": "Medium",
        "description": "JSON system configuration file exposing credentials, internal API keys, or system structure.",
        "remediation": "Restrict directory indexing and block direct access to internal configuration files.",
        "keyword": "{"
    },
    {
        "path": "/backup.sql",
        "severity": "High",
        "description": "Exposed SQL database dump files containing sensitive user details and database structures.",
        "remediation": "Avoid storing database backup files directly within public webroot directories.",
        "keyword": "CREATE TABLE"
    },
    {
        "path": "/db.sql",
        "severity": "High",
        "description": "SQL database dump exposure leaking user tables and application details.",
        "remediation": "Remove database dump dumps from target folder.",
        "keyword": "INSERT INTO"
    },
    {
        "path": "/dump.sql",
        "severity": "High",
        "description": "Exposed backup database script.",
        "remediation": "Block SQL dumps from public exposure.",
        "keyword": "CREATE TABLE"
    },
    {
        "path": "/database.sql",
        "severity": "High",
        "description": "Exposed backup SQL script.",
        "remediation": "Block SQL database backup scripts.",
        "keyword": "INSERT INTO"
    },
    {
        "path": "/.env.local",
        "severity": "High",
        "description": "Local environment variables configuration leaking tokens and passwords.",
        "remediation": "Restrict folder access to hidden files.",
        "keyword": "PORT="
    },
    {
        "path": "/.env.production",
        "severity": "High",
        "description": "Production environment configurations leaking live database and third-party tokens.",
        "remediation": "Restrict folder access.",
        "keyword": "NODE_ENV"
    },
    {
        "path": "/composer.json",
        "severity": "Low",
        "description": "Composer dependencies file exposing exact internal package versions and versions list.",
        "remediation": "Restrict access to dependencies configurations to reduce reconnaissance footprint.",
        "keyword": "require"
    },
    {
        "path": "/package.json",
        "severity": "Low",
        "description": "NPM dependencies list revealing technology stack and version identifiers.",
        "remediation": "Restrict access to NPM dependencies configurations.",
        "keyword": "dependencies"
    },
    {
        "path": "/server-status",
        "severity": "Medium",
        "description": "Apache server status page exposing loaded server endpoints, active requests, and client IP list.",
        "remediation": "Disable mod_status or restrict access to local network addresses only.",
        "keyword": "Apache Server Status"
    },
    {
        "path": "/phpinfo.php",
        "severity": "Medium",
        "description": "Exposed PHP Info config debug script revealing internal environment variables, extensions, and paths.",
        "remediation": "Delete phpinfo debug scripts on production systems.",
        "keyword": "PHP Version"
    },
    {
        "path": "/info.php",
        "severity": "Medium",
        "description": "Exposed phpinfo output debug script.",
        "remediation": "Delete debug helper scripts.",
        "keyword": "phpinfo()"
    },
    {
        "path": "/Dockerfile",
        "severity": "Medium",
        "description": "Docker blueprint configuration exposing build steps, system packages, and base configurations.",
        "remediation": "Restrict direct access to local Docker files.",
        "keyword": "FROM "
    },
    {
        "path": "/README.md",
        "severity": "Low",
        "description": "Documentation file exposing internal build commands, technology notes, or repository paths.",
        "remediation": "Remove default system repository documentations from production webroot.",
        "keyword": "#"
    }
]

