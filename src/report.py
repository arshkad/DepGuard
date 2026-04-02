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
  border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th {{ background: #1e293b; color: white; padding: 0.75rem 1rem;
        text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8fafc; }}
  .badge {{ display: inline-block; padding: 0.2em 0.6em; border-radius: 6px;
            font-weight: 700; font-size: 0.75rem; letter-spacing: 0.04em; }}
  .badge.critical {{ background: #fee2e2; color: #dc2626; }}
  .badge.high {{ background: #ffedd5; color: #ea580c; }}
  .badge.medium {{ background: #fef9c3; color: #ca8a04; }}
  .badge.low {{ background: #dcfce7; color: #16a34a; }}
  code {{ background: #f1f5f9; padding: 0.1em 0.4em; border-radius: 4px; font-size: 0.82rem; }}
  .cve-list {{ margin-top: 0.4rem; }}
  .cve-row {{ font-size: 0.8rem; color: #475569; padding: 0.15rem 0; }}
  .cve-sev {{ color: #94a3b8; }}
  footer {{ text-align: center; margin-top: 2rem; color: #94a3b8; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>🔍 Dependency Risk Report</h1>
<div class="meta">Ecosystem: <strong>{data['ecosystem'].upper()}</strong> &nbsp;·&nbsp;
  Packages: <strong>{data['total_packages']}</strong> &nbsp;·&nbsp;
  Generated: {generated}</div>

<div class="summary-grid">
  <div class="card critical"><div class="num">{data['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{data['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{data['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{data['low']}</div><div class="label">Low</div></div>
</div>
 <thead>
    <tr>
      <th>Package</th><th>Risk</th><th>Score</th><th>CVEs</th>
      <th>Maintenance</th><th>License</th><th>Pinned</th><th>Latest</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>

<footer>Generated by dep-risk-scanner · <a href="https://github.com/yourname/dep-risk-scanner">github.com/yourname/dep-risk-scanner</a></footer>
</body>
</html>"""

