# DepGuard

**An AI-powered CLI tool that scans your project's dependencies for security vulnerabilities, 
abandoned packages, and license risks — then uses Claude to write you a plain-English risk 
summary.**

## Features

- **CVE detection** via [OSV.dev](https://osv.dev) — the same database used by GitHub Dependabot
- **Abandonment detection** — flags packages with no release in 1+ years
- **License risk analysis** — catches GPL/AGPL licenses that can complicate commercial use
- **AI narrative summary** — Claude writes a concise, actionable risk brief (optional)
- **HTML export** — shareable report for your team or portfolio
- **CI/CD ready** — non-zero exit codes for CRITICAL/HIGH/MEDIUM findings
- **Supports Python (requirements.txt, pyproject.toml) and Node (package.json)**

- ## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan the included example project
python cli.py examples/

# Scan your own project
python cli.py /path/to/your/project

# Show only HIGH and CRITICAL risks
python cli.py . --min-risk HIGH

# Get an AI-generated narrative (needs ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
python cli.py . --ai-summary

# Export an HTML report
python cli.py . --output report.html

# JSON output (great for piping to other tools)
python cli.py . --format json | jq '.results[] | select(.risk_level == "CRITICAL")'

## How to Installation

```bash
git clone https://github.com/yourname/dep-risk-scanner
cd dep-risk-scanner
pip install -e ".[dev]"
```
