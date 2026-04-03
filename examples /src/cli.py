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



