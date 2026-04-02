"""
The tests for dep-risk-scanner and these are run with: pytest tests/
"""

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import (
    parse_requirements_txt,
    parse_package_json,
    assess_license_risk,
    check_abandonment,
    score_package,
)
from src.report import generate_html_report

# ── Parser tests ──────────────────────────────────────────────────────────────

def test_parse_requirements_txt(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\nflask>=2.0\n# comment\nnumpy\n")
    deps = parse_requirements_txt(req)
    assert "requests" in deps
    assert deps["requests"] == "==2.28.0"
    assert "flask" in deps
    assert "numpy" in deps


def test_parse_package_json(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    deps = parse_package_json(pkg)
    assert "express" in deps
    assert "jest" in deps



