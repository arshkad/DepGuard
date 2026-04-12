"""
DepGuardWeb — FastAPI backend.
"""

import logging
logging.basicConfig(level=logging.DEBUG)

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.scanner import scan_repo
from src.report import generate_html_report

app = FastAPI(title="DepSentinel")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

def clone_repo(github_url: str, dest: str) -> bool:
    """Shallow-clone a public GitHub repo. Returns True on success."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", github_url, dest],
            timeout=60,
            capture_output=True,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def normalize_github_url(url: str) -> str:
    """Accept github.com/user/repo or full https URL."""
    url = url.strip().rstrip("/")
    if url.startswith("http"):
        return url
    if url.startswith("github.com"):
        return f"https://{url}"
    # assume user/repo shorthand
    if "/" in url and not url.startswith("https"):
        return f"https://github.com/{url}"
    return url

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, repo_url: str = Form(...)):
    repo_url = normalize_github_url(repo_url)

    if "github.com" not in repo_url:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please enter a valid GitHub repository URL.",
        })

    tmp_dir = tempfile.mkdtemp(prefix=f"depscan_{uuid.uuid4().hex[:8]}_")
    try:
        success = clone_repo(repo_url, tmp_dir)
        if not success:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Could not clone repository. Make sure it's public and the URL is correct.",
            })

        data = scan_repo(tmp_dir)

        if "error" in data:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": f"No supported dependency file found in this repo (requirements.txt, pyproject.toml, or package.json).",
            })

        # Optional AI summary
        ai_summary = None
        if ANTHROPIC_API_KEY:
            from src.ai_summary import generate_ai_summary
            ai_summary = generate_ai_summary(data, ANTHROPIC_API_KEY)

        return templates.TemplateResponse("results.html", {
            "request": request,
            "data": data,
            "repo_url": repo_url,
            "ai_summary": ai_summary,
            "has_ai": bool(ANTHROPIC_API_KEY),
        })
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/scan/download")
async def download_report(repo_url: str = Form(...)):
    """Return the HTML report as a downloadable file."""
    from fastapi.responses import Response
    repo_url = normalize_github_url(repo_url)
    tmp_dir = tempfile.mkdtemp(prefix="depscan_dl_")
    try:
        clone_repo(repo_url, tmp_dir)
        data = scan_repo(tmp_dir)
        html = generate_html_report(data)
        return Response(
            content=html,
            media_type="text/html",
            headers={"Content-Disposition": "attachment; filename=dep-risk-report.html"},
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)




