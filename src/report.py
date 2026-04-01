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

