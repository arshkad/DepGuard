import logging
import sys
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

import os
import tempfile
import shutil
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import requests as http_requests

from src.scanner import scan_repo
from src.report import generate_html_report
from history import add_to_history, get_history

print("✅ All imports successful", flush=True)

app = FastAPI(title="DepGuard")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

DEPENDENCY_FILES = [
    "requirements.txt",
    "pyproject.toml",
    "package.json",
]


def parse_github_url(url: str) -> tuple[str, str] | None:
    url = url.strip().rstrip("/")
    for prefix in ["https://github.com/", "http://github.com/", "github.com/"]:
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    parts = url.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None


def fetch_file_from_github(owner: str, repo: str, filename: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filename}"
    try:
        resp = http_requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{filename}"
        resp = http_requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except http_requests.RequestException as e:
        print(f"Error fetching {filename}: {e}", flush=True)
    return None


def fetch_repo_deps(owner: str, repo: str) -> tuple[str, str] | None:
    for filename in DEPENDENCY_FILES:
        content = fetch_file_from_github(owner, repo, filename)
        if content:
            print(f"Found {filename} in {owner}/{repo}", flush=True)
            return filename, content
    return None


def scan_from_github(owner: str, repo: str) -> dict:
    result = fetch_repo_deps(owner, repo)
    if not result:
        return {"error": "No supported dependency file found (requirements.txt, pyproject.toml, or package.json)."}

    filename, content = result
    tmp_dir = tempfile.mkdtemp(prefix="depguard_")
    try:
        dep_file = Path(tmp_dir) / filename
        dep_file.write_text(content)
        return scan_repo(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "history": get_history(),
    })


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, repo_url: str = Form(...)):
    import traceback

    repo_url = repo_url.strip()
    parsed = parse_github_url(repo_url)

    if not parsed:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please enter a valid GitHub repository URL (e.g. github.com/user/repo).",
            "history": get_history(),
        })

    owner, repo = parsed
    print(f"Scanning {owner}/{repo}", flush=True)

    try:
        data = scan_from_github(owner, repo)

        if "error" in data:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": data["error"],
                "history": get_history(),
            })

        add_to_history(f"https://github.com/{owner}/{repo}", data)

        ai_summary = None
        if ANTHROPIC_API_KEY:
            from src.ai_summary import generate_ai_summary
            ai_summary = generate_ai_summary(data, ANTHROPIC_API_KEY)

        return templates.TemplateResponse("results.html", {
            "request": request,
            "data": data,
            "repo_url": f"https://github.com/{owner}/{repo}",
            "ai_summary": ai_summary,
        })

    except Exception as e:
        print(f"SCAN ERROR: {e}", flush=True)
        traceback.print_exc()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Scan failed: {str(e)}",
            "history": get_history(),
        })


@app.post("/scan/download")
async def download_report(repo_url: str = Form(...)):
    parsed = parse_github_url(repo_url)
    if not parsed:
        return Response(content="Invalid URL", status_code=400)
    owner, repo = parsed
    data = scan_from_github(owner, repo)
    html = generate_html_report(data)
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=depguard-report.html"},
    )


@app.get("/badge/{owner}/{repo}")
async def badge(owner: str, repo: str):
    try:
        data = scan_from_github(owner, repo)

        if "error" in data:
            label, status, color = "depguard", "unknown", "#9e9e9e"
        elif data["critical"] > 0:
            label, status, color = "depguard", f"{data['critical']} critical", "#e53935"
        elif data["high"] > 0:
            label, status, color = "depguard", f"{data['high']} high", "#f97316"
        elif data["medium"] > 0:
            label, status, color = "depguard", f"{data['medium']} medium", "#f59e0b"
        else:
            label, status, color = "depguard", "secure", "#22c55e"

    except Exception as e:
        print(f"Badge error: {e}", flush=True)
        label, status, color = "depguard", "error", "#9e9e9e"

    label_width = len(label) * 7 + 10
    status_width = len(status) * 7 + 10
    total_width = label_width + status_width

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{status_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_width // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_width // 2}" y="14">{label}</text>
    <text x="{label_width + status_width // 2}" y="15" fill="#010101" fill-opacity=".3">{status}</text>
    <text x="{label_width + status_width // 2}" y="14">{status}</text>
  </g>
</svg>"""

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=3600"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))