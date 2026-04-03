#!/usr/bin/env python3
"""
DepGuard- a type of dep-risk-scanner which is an AI-powered dependency risk analysis CLI.

Usage:
    python cli.py .                          # scan current directory
    python cli.py /path/to/project           # scan a project
    python cli.py . --format json            # JSON output
    python cli.py . --min-risk HIGH          # only show HIGH+ risks
    python cli.py . --ai-summary             # include Claude AI narrative summary
    python cli.py . --output report.html     # export HTML report
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent))
from src.scanner import scan_repo
from src.ai_summary import generate_ai_summary
from src.report import generate_html_report
console = Console() if HAS_RICH else None

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def filter_by_risk(results: list, min_risk: str) -> list:
    threshold = RISK_ORDER.get(min_risk, 3)
    return [r for r in results if RISK_ORDER.get(r["risk_level"], 3) <= threshold]


def print_rich_report(data: dict, min_risk: str):
    results = filter_by_risk(data["results"], min_risk)

    # Header panel
    total = data["total_packages"]
    summary_line = (
        f"[bold red]{data['critical']} CRITICAL[/]  "
        f"[red]{data['high']} HIGH[/]  "
        f"[yellow]{data['medium']} MEDIUM[/]  "
        f"[green]{data['low']} LOW[/]"
    )
    console.print(Panel(
        f"[bold]Ecosystem:[/] {data['ecosystem'].upper()}   "
        f"[bold]Packages scanned:[/] {total}\n\n{summary_line}",
        title="[bold cyan]🔍 Dependency Risk Report[/]",
        border_style="cyan",
    ))

    if not results:
        console.print("[green]✅ No packages found at or above the specified risk threshold.[/]")
        return
    # Main table
    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Risk", justify="center", min_width=10)
    table.add_column("Score", justify="center", min_width=7)
    table.add_column("CVEs", justify="center", min_width=5)
    table.add_column("Maintenance", min_width=12)
    table.add_column("License Risk", min_width=12)
    table.add_column("Pinned Version", min_width=14)

    for r in results:
        level = r["risk_level"]
        color = RISK_COLORS.get(level, "white")
        emoji = RISK_EMOJI.get(level, "⚪")

        maint_color = {"abandoned": "red", "stale": "yellow", "active": "green"}.get(
            r["maintenance"], "dim"
        )
        lic_color = {"high": "red", "medium": "yellow", "low": "green"}.get(
            r["license_risk"], "dim"
        )

        table.add_row(
            r["package"],
            f"[{color}]{emoji} {level}[/]",
            f"[{color}]{r['risk_score']}[/]",
            str(r["vulnerability_count"]),
            f"[{maint_color}]{r['maintenance']}[/]",
            f"[{lic_color}]{r['license_risk']}[/]",
        )

    console.print(table)
    # Expand CVE details for CRITICAL/HIGH
    for r in results:
        if r["risk_level"] in ("CRITICAL", "HIGH") and r["vulnerabilities"]:
            console.print(f"\n[bold red]⚠ CVEs for {r['package']}:[/]")
            for v in r["vulnerabilities"]:
                sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(
                    v["severity"], "white"
                )
                console.print(
                    f"  [{sev_color}]• {v['id']}[/] [{v['severity']}] — {v['summary']}"
                )


def print_plain_report(data: dict, min_risk: str):
    results = filter_by_risk(data["results"], min_risk)
    print(f"\n=== Dependency Risk Report ===")
    print(f"Ecosystem: {data['ecosystem'].upper()}")
    print(f"Packages:  {data['total_packages']}")
    print(f"CRITICAL: {data['critical']}  HIGH: {data['high']}  MEDIUM: {data['medium']}  LOW: {data['low']}\n")
    for r in results:
        print(f"[{r['risk_level']:8}] {r['package']:30} score={r['risk_score']:3}  "
              f"cves={r['vulnerability_count']}  maint={r['maintenance']}  "
              f"license_risk={r['license_risk']}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered dependency risk scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog=__doc__,
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to repo (default: .)")
    parser.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--min-risk", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW",
        help="Minimum risk level to display (default: LOW)"
    )
    parser.add_argument(
        "--ai-summary", action="store_true",
        help="Generate an AI narrative summary using Claude (requires ANTHROPIC_API_KEY)"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Export HTML report to a file (e.g., report.html)"
    )
    args = parser.parse_args()

    repo_path = Path(args.path).resolve()
    if not repo_path.exists():
        print(f"Error: path '{repo_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if HAS_RICH:
        with console.status(f"[cyan]Scanning {repo_path} ...[/]", spinner="dots"):
            data = scan_repo(str(repo_path))
    else:
        print(f"Scanning {repo_path} ...")
        data = scan_repo(str(repo_path))

    if "error" in data:
        print(f"Error: {data['error']}", file=sys.stderr)
        sys.exit(1)
    # Output
    if args.format == "json":
        print(json.dumps(data, indent=2))
    else:
        if HAS_RICH:
            print_rich_report(data, args.min_risk)
        else:
            print_plain_report(data, args.min_risk)

    # AI narrative
    if args.ai_summary:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("\n⚠ ANTHROPIC_API_KEY not set. Skipping AI summary.", file=sys.stderr)
        else:
            if HAS_RICH:
                with console.status("[cyan]Generating AI summary...[/]", spinner="dots"):
                    summary = generate_ai_summary(data, api_key)
            else:
                print("\nGenerating AI summary...")
                summary = generate_ai_summary(data, api_key)

            if HAS_RICH:
                console.print(Panel(summary, title="[bold magenta]🤖 AI Risk Summary[/]", border_style="magenta"))
            else:
                print("\n=== AI Risk Summary ===")
                print(summary)
    # HTML report
    if args.output:
        html = generate_html_report(data)
        Path(args.output).write_text(html)
        if HAS_RICH:
            console.print(f"\n[green]✅ HTML report saved to {args.output}[/]")
        else:
            print(f"\nHTML report saved to {args.output}")

    # Exit code reflects risk level
    if data["critical"] > 0:
        sys.exit(3)
    elif data["high"] > 0:
        sys.exit(2)
    elif data["medium"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()










