"""
Core dependency risk scanning logic.
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import requests


# ── Parsers ──────────────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> dict[str, str]:
    deps = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, <=, ~=, !=, >
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~]+.*)?$", line)
        if match:
            name, version = match.group(1), (match.group(2) or "").strip()
            deps[name] = version
    return deps


def parse_pyproject_toml(path: Path) -> dict[str, str]:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore

    data = tomllib.loads(path.read_text())
    deps = {}
    raw = (
        data.get("project", {}).get("dependencies", [])
    )
    if isinstance(raw, list):
        for dep in raw:
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~]+.*)?$", dep.strip())
            if match:
                deps[match.group(1)] = (match.group(2) or "").strip()
    elif isinstance(raw, dict):
        for name, ver in raw.items():
            if name.lower() != "python":
                deps[name] = str(ver)
    return deps


