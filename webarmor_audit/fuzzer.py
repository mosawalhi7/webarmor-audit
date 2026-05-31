"""
Smart vulnerability fuzzer for WebArmor-Audit.
Concurrently scans sensitive webroot directories and validates responses
using body keywords to filter out custom 404/error pages.
"""

from __future__ import annotations

import concurrent.futures
from urllib.parse import urljoin, urlparse
import requests

from webarmor_audit.constants import DEFAULT_TIMEOUT, FUZZ_PATHS, USER_AGENT
from webarmor_audit.models import FuzzFinding


def _fuzz_single_path(
    base_url: str,
    item: dict,
    timeout: int,
    verify_ssl: bool,
) -> FuzzFinding | None:
    """Scan a single path, verify keywords, and return a FuzzFinding if exposed."""
    path = item["path"]
    target_url = urljoin(base_url, path)
    
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }
    
    try:
        # Don't follow redirects too far to avoid getting stuck or redirected to homepage login
        response = requests.get(
            target_url,
            headers=headers,
            timeout=min(4, timeout),
            verify=verify_ssl,
            allow_redirects=False,
        )
        
        # We only consider 200 OK or 206 Partial Content (and sometimes 403 Forbidden for directory listing)
        if response.status_code == 200:
            content_sample = response.content[:2000].decode("utf-8", errors="ignore")
            keyword = item["keyword"]
            
            # Simple signature verification to filter out fake '200 OK' error custom pages
            if keyword in content_sample:
                return FuzzFinding(
                    path=path,
                    status_code=response.status_code,
                    is_exposed=True,
                    severity=item["severity"],
                    description=item["description"],
                    remediation=item["remediation"]
                )
    except requests.RequestException:
        pass
        
    return None


def run_smart_fuzz(
    base_url: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> list[FuzzFinding]:
    """
    Scan target URL concurrently for sensitive exposures using ThreadPoolExecutor.
    """
    findings: list[FuzzFinding] = []
    
    # Extract clean base URL path
    parsed = urlparse(base_url)
    clean_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if not clean_base.endswith("/"):
        # If it points to index.html or similar, strip filename
        if parsed.path and not parsed.path.endswith("/"):
            pos = clean_base.rfind("/")
            clean_base = clean_base[:pos+1]
        else:
            clean_base += "/"

    # Use a ThreadPoolExecutor with up to 10 workers to scan in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_fuzz_single_path, clean_base, item, timeout, verify_ssl): item
            for item in FUZZ_PATHS
        }
        
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res is not None:
                    findings.append(res)
            except Exception:
                pass
                
    # Sort findings by severity (High -> Medium -> Low)
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda x: severity_order.get(x.severity, 3))
    
    return findings
