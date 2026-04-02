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

        rows += f"""
        <tr>
          <td><strong>{r['package']}</strong>
            {f'<div class="cve-list">{cve_details}</div>' if cve_details else ""}
          </td>
          <td>{badge}</td>
          <td><strong>{r['risk_score']}</strong>/100</td>
          <td>{cve_cell}</td>
          <td style="color:{mc}">{r['maintenance']}</td>
          <td style="color:{lc}">{r['license_risk']}<br><small style="color:#6b7280">{r.get('license','')[:30]}</small></td>
          <td><code>{r['pinned_version'] or 'unpinned'}</code></td>
          <td><code>{r['latest_version']}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dependency Risk Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8fafc; color: #1e293b; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #64748b; margin-bottom: 2rem; font-size: 0.9rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: white; border-radius: 12px; padding: 1.25rem; text-align: center;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  .card .num {{ font-size: 2.5rem; font-weight: 700; line-height: 1; }}
  .card .label {{ font-size: 0.8rem; color: #64748b; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card.critical .num {{ color: #dc2626; }}
  .card.high .num {{ color: #ea580c; }}
  .card.medium .num {{ color: #ca8a04; }}

