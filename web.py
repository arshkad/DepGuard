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
 
print("✅ All imports successful", flush=True)
 
app = FastAPI(title="DepGuard")
 
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
 
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
 
# Files we look for in priority order
DEPENDENCY_FILES = [
    "requirements.txt",
    "pyproject.toml",
    "package.json",
]
 
 
def parse_github_url(url: str) -> tuple[str, str] | None:
    """Extract owner and repo from a GitHub URL. Returns (owner, repo) or None."""
    url = url.strip().rstrip("/")
    # Handle: https://github.com/owner/repo or github.com/owner/repo or owner/repo
    for prefix in ["https://github.com/", "http://github.com/", "github.com/"]:
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    parts = url.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None
 
 
def fetch_file_from_github(owner: str, repo: str, filename: str) -> str | None:
    """Fetch a file's raw content from a public GitHub repo."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filename}"
    try:
        resp = http_requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
        # Try master branch as fallback
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{filename}"
        resp = http_requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except http_requests.RequestException as e:
        print(f"Error fetching {filename}: {e}", flush=True)
    return None
 
 
def fetch_repo_deps(owner: str, repo: str) -> tuple[str, str] | None:
    """
    Try to fetch a dependency file from the repo.
    Returns (filename, content) or None if nothing found.
    """
    for filename in DEPENDENCY_FILES:
        content = fetch_file_from_github(owner, repo, filename)
        if content:
            print(f"Found {filename} in {owner}/{repo}", flush=True)
            return filename, content
    return None
 
 
def scan_from_github(owner: str, repo: str) -> dict:
    """Download dep file and scan it without cloning."""
    result = fetch_repo_deps(owner, repo)
    if not result:
        return {"error": "No supported dependency file found (requirements.txt, pyproject.toml, or package.json)."}
 
    filename, content = result
 
    # Write to a temp dir so scanner can read it
    tmp_dir = tempfile.mkdtemp(prefix="depguard_")
    try:
        dep_file = Path(tmp_dir) / filename
        dep_file.write_text(content)
        return scan_repo(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
 
 
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
 
 
@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, repo_url: str = Form(...)):
    import traceback
 
    repo_url = repo_url.strip()
    parsed = parse_github_url(repo_url)
 
    if not parsed:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please enter a valid GitHub repository URL (e.g. github.com/user/repo).",
        })
 
    owner, repo = parsed
    print(f"Scanning {owner}/{repo}", flush=True)
 
    try:
        data = scan_from_github(owner, repo)
 
        if "error" in data:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": data["error"],
            })
 
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
 
 
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
 