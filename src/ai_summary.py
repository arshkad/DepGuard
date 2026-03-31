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
                }

    system_prompt = (
        "You are a senior application security engineer. "
        "You receive structured dependency scan results and write a concise, "
        "actionable risk summary for developers. Be specific: name packages, "
        "CVEs, and concrete remediation steps. Keep it under 300 words. "
        "Use plain text only — no markdown headers or bullet symbols."
    )

    user_prompt = (
        f"Here are the dependency scan results:\n\n"
        f"{json.dumps(prompt_data, indent=2)}\n\n"
        "Write a clear risk summary covering: overall posture, the top 3 most "
        "urgent issues and why, and immediate next steps the developer should take."
    )

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 512,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json().get("content", [])
        return " ".join(block["text"] for block in content if block["type"] == "text")
    except requests.RequestException as e:
        return f"[AI summary unavailable: {e}]"


