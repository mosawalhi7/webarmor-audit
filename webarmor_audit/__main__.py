"""
Allow running the package directly via ``python -m webarmor_audit``.
"""

import sys

from webarmor_audit.cli import run

if __name__ == "__main__":
    sys.exit(run())
