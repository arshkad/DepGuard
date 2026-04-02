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



# ── License risk tests ────────────────────────────────────────────────────────

def test_license_mit():
    assert assess_license_risk("MIT") == "low"

def test_license_gpl():
    assert assess_license_risk("GPL-3.0") == "high"

def test_license_unknown():
    assert assess_license_risk("") == "unknown"
    assert assess_license_risk("Unknown") == "unknown"


# ── Abandonment tests ─────────────────────────────────────────────────────────

def test_active_package():
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    assert check_abandonment(recent) == "active"

def test_stale_package():
    from datetime import datetime, timezone, timedelta
    stale = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
    assert check_abandonment(stale) == "stale"

def test_abandoned_package():
    from datetime import datetime, timezone, timedelta
    old = (datetime.now(timezone.utc) - timedelta(days=800)).isoformat()
    assert check_abandonment(old) == "abandoned"

def test_no_release_date():
    assert check_abandonment(None) == "unknown"
# ── Score tests ───────────────────────────────────────────────────────────────

def test_score_clean_package():
    score, level = score_package([], "active", "low")
    assert score == 0
    assert level == "LOW"

def test_score_risky_package():
    vulns = [{"database_specific": {"severity": "CRITICAL"}}] * 2
    score, level = score_package(vulns, "abandoned", "high")
    assert score >= 60
    assert level == "CRITICAL"

def test_score_medium():
    vulns = [{"database_specific": {"severity": "MEDIUM"}}]
    score, level = score_package(vulns, "stale", "low")
    assert level in ("MEDIUM", "HIGH")







