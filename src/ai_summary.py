"""
Generate an AI-powered narrative risk summary using the Anthropic API.
"""

import json
import requests


def generate_ai_summary(scan_data: dict, api_key: str) -> str:
    """
    Send scan results to Claude and get back a plain-English risk narrative.
    """
    # Build a compact summary for the prompt
    top_risky = [
        r for r in scan_data["results"]
        if r["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM")
    ][:10]

    prompt_data = {
        "ecosystem": scan_data["ecosystem"],
        "total_packages": scan_data["total_packages"],
        "critical": scan_data["critical"],
        "high": scan_data["high"],
        "medium": scan_data["medium"],
        "low": scan_data["low"],
        "top_risks": [
            {
                "package": r["package"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "vulnerability_count": r["vulnerability_count"],
                "maintenance": r["maintenance"],
                "license_risk": r["license_risk"],
                "license": r["license"],
                "top_cves": [
                    {"id": v["id"], "severity": v["severity"], "summary": v["summary"]}
                    for v in r["vulnerabilities"][:3]
                ],
            }
            for r in top_risky
