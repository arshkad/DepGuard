"""
The tests for dep-risk-scanner and these are run with: pytest tests/
"""

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import (
    parse_requirements_txt,
    parse_package_json,
    assess_license_risk,
    check_abandonment,
    score_package,
)
from src.report import generate_html_report

