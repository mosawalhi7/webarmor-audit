#!/usr/bin/env python3
"""
WebArmor-Audit — HTTP Security Headers & SSL Auditor.

Convenience script entry point.  Equivalent to running:

    python -m webarmor_audit <URL>

Usage:
    python main.py https://example.com
    python main.py https://example.com -o my_report.md --timeout 20
"""

import sys

from webarmor_audit.cli import run


def main() -> None:
    """Invoke the CLI and propagate the exit code."""
    sys.exit(run())


if __name__ == "__main__":
    main()
