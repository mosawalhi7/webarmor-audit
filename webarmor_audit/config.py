"""
Configuration profile parser for WebArmor-Audit.
"""

import os
from typing import Any, Dict


def parse_simple_toml(content: str) -> Dict[str, Any]:
    """
    Fallback TOML parser for environments without tomllib (Python < 3.11).
    
    Parses simple flat and nested TOML sections.
    """
    result: Dict[str, Any] = {}
    current_section = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        # Section header e.g. [headers]
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            result[current_section] = {}
            continue

        # Key-value pair
        if "=" in line:
            parts = line.split("=", 1)
            key = parts[0].strip()
            if (key.startswith('"') and key.endswith('"')) or (
                key.startswith("'") and key.endswith("'")
            ):
                key = key[1:-1]
            val_str = parts[1].strip()

            # Handle quoted strings
            if (val_str.startswith('"') and val_str.endswith('"')) or (
                val_str.startswith("'") and val_str.endswith("'")
            ):
                value: Any = val_str[1:-1]
            elif val_str.lower() == "true":
                value = True
            elif val_str.lower() == "false":
                value = False
            else:
                try:
                    if "." in val_str:
                        value = float(val_str)
                    else:
                        value = int(val_str)
                except ValueError:
                    value = val_str

            if current_section:
                result[current_section][key] = value
            else:
                result[key] = value

    return result


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load a custom audit profile from a TOML file.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Try to use standard tomllib first (available in Python 3.11+)
        try:
            import tomllib  # type: ignore
            return tomllib.loads(content)
        except ImportError:
            # Try to use tomli as a backup
            try:
                import tomli as tomllib  # type: ignore
                return tomllib.loads(content)
            except ImportError:
                # Fall back to custom lightweight parser
                return parse_simple_toml(content)

    except Exception as e:
        raise ValueError(f"Error parsing configuration profile: {str(e)}")


def apply_profile(config: Dict[str, Any]) -> None:
    """
    Apply a loaded profile configuration to override security header weights
    and grade thresholds.
    """
    from webarmor_audit.constants import SECURITY_HEADERS, GRADE_THRESHOLDS

    # Override header weights
    headers_config = config.get("headers", {})
    for header_name, weight in headers_config.items():
        found = False
        for k in list(SECURITY_HEADERS.keys()):
            if k.lower() == header_name.lower():
                SECURITY_HEADERS[k]["weight"] = int(weight)
                found = True
                break
        if not found:
            # Register user-defined custom header
            SECURITY_HEADERS[header_name] = {
                "weight": int(weight),
                "description": f"Custom tracked header '{header_name}'.",
                "recommended": "Verify configuration meets organization standards."
            }

    # Override grade thresholds
    thresholds_config = config.get("thresholds", {})
    if thresholds_config:
        new_thresholds = []
        for grade, score in thresholds_config.items():
            new_thresholds.append((int(score), grade.upper()))
        # Sort descending by score
        new_thresholds.sort(reverse=True, key=lambda x: x[0])
        
        GRADE_THRESHOLDS.clear()
        GRADE_THRESHOLDS.extend(new_thresholds)

