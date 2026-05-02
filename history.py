"""
Scan history — stores the last 20 scanned repos in a local JSON file.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

HISTORY_FILE = Path("/tmp/depguard_history.json")
MAX_HISTORY = 20


def load_history() -> list:
    try:
        if HISTORY_FILE.exists():
            return json.loads(HISTORY_FILE.read_text())
    except Exception:
        pass
    return []


def save_history(history: list):
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except Exception as e:
        print(f"Could not save history: {e}", flush=True)


def add_to_history(repo_url: str, data: dict):
    """Add a scan result to history."""
    history = load_history()

    # Remove duplicate if already exists
    history = [h for h in history if h.get("repo_url") != repo_url]

    # Add new entry at the top
    history.insert(0, {
        "repo_url": repo_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "critical": data.get("critical", 0),
        "high": data.get("high", 0),
        "medium": data.get("medium", 0),
        "low": data.get("low", 0),
        "total": data.get("total_packages", 0),
        "ecosystem": data.get("ecosystem", "unknown"),
    })

    # Keep only the last MAX_HISTORY entries
    history = history[:MAX_HISTORY]
    save_history(history)


def get_history() -> list:
    return load_history()