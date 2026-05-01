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
               or data.get("tool", {}).get("poetry", {}).get("dependencies", {})
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


def parse_package_json(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))
    return deps


def detect_and_parse(repo_path: Path) -> tuple[dict[str, str], str]:
    """Auto-detect dependency file and parse it. Returns (deps, ecosystem)."""
    checks = [
        ("requirements.txt", parse_requirements_txt, "pypi"),
        ("pyproject.toml", parse_pyproject_toml, "pypi"),
        ("package.json", parse_package_json, "npm"),
    ]
    for filename, parser, ecosystem in checks:
        candidate = repo_path / filename
        if candidate.exists():
            return parser(candidate), ecosystem
    return {}, "unknown"


# ── OSV Vulnerability Lookup ─────────────────────────────────────────────────

def query_osv(package_name: str, ecosystem: str) -> list[dict]:
    """Query OSV.dev for known vulnerabilities."""
    eco_map = {"pypi": "PyPI", "npm": "npm"}
    eco = eco_map.get(ecosystem, "PyPI")
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name, "ecosystem": eco}},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except requests.RequestException:
        pass
    return []


# ── PyPI Metadata ────────────────────────────────────────────────────────────

def get_pypi_metadata(package_name: str) -> dict:
    """Fetch package metadata from PyPI."""
    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{package_name}/json", timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            latest_version = info.get("version", "unknown")
            latest_release = releases.get(latest_version, [{}])
            upload_time = None
            if latest_release:
                upload_time = latest_release[-1].get("upload_time", None)
            return {
                "version": latest_version,
                "last_release": upload_time,
                "home_page": info.get("home_page") or info.get("project_url"),
                "license": info.get("license", "Unknown"),
                "summary": info.get("summary", ""),
            }
    except requests.RequestException:
                pass
    return {}


# ── License Risk ─────────────────────────────────────────────────────────────

RISKY_LICENSES = {
    "GPL-3.0", "GPL-2.0", "AGPL-3.0", "LGPL-3.0",
    "LGPL-2.1", "CC-BY-SA-4.0", "EUPL-1.2",
}
SAFE_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "CC0-1.0", "PSF",
}


def assess_license_risk(license_str: str) -> str:
    if not license_str or license_str == "Unknown":
        return "unknown"
    for lic in RISKY_LICENSES:
        if lic.lower() in license_str.lower():
            return "high"
    for lic in SAFE_LICENSES:
        if lic.lower() in license_str.lower():
            return "low"
    return "medium"


# ── Abandonment Detection ────────────────────────────────────────────────────
def check_abandonment(last_release: Optional[str]) -> str:
    """Return 'active', 'stale', or 'abandoned' based on last release date."""
    if not last_release:
        return "unknown"
    from datetime import datetime, timezone
    try:
        release_dt = datetime.fromisoformat(last_release.replace("Z", "+00:00"))
        # Make sure both datetimes are timezone-aware
        if release_dt.tzinfo is None:
            release_dt = release_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_since = (now - release_dt).days
        if days_since < 365:
            return "active"
        elif days_since < 730:
            return "stale"
        else:
            return "abandoned"
    except ValueError:
        return "unknown"


# ── Per-Package Risk Score ────────────────────────────────────────────────────

def score_package(vulns: list, maintenance: str, license_risk: str) -> tuple[int, str]:
    """
    Returns (score 0-100, risk_level).
    Higher score = higher risk.
    """
    score = 0

    # Vulnerability scoring
    severity_map = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
    for v in vulns:
        sev = v.get("database_specific", {}).get("severity", "MEDIUM").upper()
        score += severity_map.get(sev, 10)

    # Maintenance scoring
    score += {"abandoned": 30, "stale": 15, "unknown": 10, "active": 0}.get(maintenance, 0)

    # License scoring
    score += {"high": 20, "medium": 10, "unknown": 5, "low": 0}.get(license_risk, 0)

    score = min(score, 100)

    if score >= 60:
        level = "CRITICAL"
    elif score >= 35:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


# ── Main Scan Orchestrator ────────────────────────────────────────────────────

def scan_repo(repo_path: str) -> dict:
    path = Path(repo_path)
    deps, ecosystem = detect_and_parse(path)

    if not deps:
        return {"error": "No supported dependency file found.", "results": []}

    results = []
    for package, pinned_version in deps.items():
        meta = get_pypi_metadata(package) if ecosystem == "pypi" else {}
        vulns = query_osv(package, ecosystem)
        maintenance = check_abandonment(meta.get("last_release"))
        license_risk = assess_license_risk(meta.get("license", ""))
        score, level = score_package(vulns, maintenance, license_risk)

        results.append({
            "package": package,
            "pinned_version": pinned_version,
            "latest_version": meta.get("version", "unknown"),
            "vulnerability_count": len(vulns),
            "vulnerabilities": [
                {
                    "id": v.get("id", ""),
                    "summary": v.get("summary", "")[:120],
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                }
                for v in vulns[:5]  # cap at 5 per package
            ],
            "maintenance": maintenance,
            "last_release": meta.get("last_release", "unknown"),
            "license": meta.get("license", "Unknown"),
            "license_risk": license_risk,
            "risk_score": score,
            "risk_level": level,
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "ecosystem": ecosystem,
        "total_packages": len(results),
        "critical": sum(1 for r in results if r["risk_level"] == "CRITICAL"),
        "high": sum(1 for r in results if r["risk_level"] == "HIGH"),
        "medium": sum(1 for r in results if r["risk_level"] == "MEDIUM"),
        "low": sum(1 for r in results if r["risk_level"] == "LOW"),
        "results": results,
    }







