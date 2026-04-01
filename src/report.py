"""
This generates a self-contained HTML report from scan results.
"""

from datetime import datetime


RISK_BADGE = {
    "CRITICAL": ('<span class="badge critical">CRITICAL</span>', "#dc2626"),
    "HIGH":     ('<span class="badge high">HIGH</span>',         "#ea580c"),
    "MEDIUM":   ('<span class="badge medium">MEDIUM</span>',     "#ca8a04"),
    "LOW":      ('<span class="badge low">LOW</span>',           "#16a34a"),
}

MAINT_COLOR = {
    "abandoned": "#dc2626",
    "stale":     "#ca8a04",
    "active":    "#16a34a",
    "unknown":   "#6b7280",
}

def generate_html_report(data: dict) -> str:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = data["results"]

    rows = ""
    for r in results:
        badge, _ = RISK_BADGE.get(r["risk_level"], RISK_BADGE["LOW"])
        mc = MAINT_COLOR.get(r["maintenance"], "#6b7280")
        lc = {"high": "#dc2626", "medium": "#ca8a04", "low": "#16a34a"}.get(
            r["license_risk"], "#6b7280"
        )
        cve_count = r["vulnerability_count"]
        cve_cell = f'<span style="color:#dc2626;font-weight:600">{cve_count}</span>' if cve_count else "0"

        cve_details = ""
        for v in r.get("vulnerabilities", []):
            sc = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04"}.get(v["severity"], "#6b7280")
            cve_details += (
                f'<div class="cve-row">'
                f'<span style="color:{sc};font-weight:600">{v["id"]}</span> '
                f'<span class="cve-sev">[{v["severity"]}]</span> — {v["summary"]}'
                f"</div>"
            )
