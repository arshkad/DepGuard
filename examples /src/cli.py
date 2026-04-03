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


