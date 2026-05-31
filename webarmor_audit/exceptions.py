"""
Custom exception classes for WebArmor-Audit.

Provides granular error handling for network, SSL, and validation failures
so the CLI can present user-friendly diagnostics instead of raw tracebacks.
"""


class WebArmorError(Exception):
    """Base exception for all WebArmor-Audit errors."""


class InvalidURLError(WebArmorError):
    """Raised when the target URL fails validation."""

    def __init__(self, url: str, reason: str = "Malformed or unsupported URL") -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Invalid URL '{url}': {reason}")


class ConnectionError(WebArmorError):
    """Raised when the HTTP connection to the target fails."""

    def __init__(self, url: str, reason: str = "Connection refused or unreachable") -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Connection failed for '{url}': {reason}")


class SSLCertificateError(WebArmorError):
    """Raised when SSL certificate retrieval or parsing fails."""

    def __init__(self, hostname: str, reason: str = "Unable to retrieve certificate") -> None:
        self.hostname = hostname
        self.reason = reason
        super().__init__(f"SSL error for '{hostname}': {reason}")


class TimeoutError(WebArmorError):
    """Raised when a request exceeds the configured timeout threshold."""

    def __init__(self, url: str, timeout: int) -> None:
        self.url = url
        self.timeout = timeout
        super().__init__(f"Request to '{url}' timed out after {timeout}s")
