import logging
import sys
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

try:
    from fastapi import FastAPI, Request, Form
    from fastapi.responses import HTMLResponse, Response
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from src.scanner import scan_repo
    from src.report import generate_html_report
    print("All imports successful", flush=True)
except Exception as e:
    print(f"Import error: {e}", flush=True)
    sys.exit(1)

app = FastAPI(title="DepGuard")

BASE_DIR = Path(__file__).parent

from jinja2 import Environment, FileSystemLoader
from starlette.templating import Jinja2Templates

jinja_env = Environment(loader=FileSystemLoader(str(BASE_DIR / "templates")))
templates = Jinja2Templates(env=jinja_env)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def clone_repo(github_url: str, dest: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", github_url, dest],
            timeout=60, capture_output=True,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def normalize_github_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if url.startswith("http"):
        return url
    if url.startswith("github.com"):
        return f"https://{url}"
    if "/" in url:
        return f"https://github.com/{url}"
    return url


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, repo_url: str = Form(...)):
    import traceback
    repo_url = normalize_github_url(repo_url)
    if "github.com" not in repo_url:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please enter a valid GitHub repository URL.",
        })
    tmp_dir = tempfile.mkdtemp(prefix=f"depguard_{uuid.uuid4().hex[:8]}_")
    try:
        if not clone_repo(repo_url, tmp_dir):
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Could not clone repository. Make sure it's public and the URL is correct.",
            })
        data = scan_repo(tmp_dir)
        if "error" in data:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "No supported dependency file found.",
            })
        ai_summary = None
        if ANTHROPIC_API_KEY:
            from src.ai_summary import generate_ai_summary
            ai_summary = generate_ai_summary(data, ANTHROPIC_API_KEY)
        return templates.TemplateResponse("results.html", {
            "request": request,
            "data": data,
            "repo_url": repo_url,
            "ai_summary": ai_summary,
        })
    except Exception as e:
        print(f"SCAN ERROR: {e}", flush=True)
        traceback.print_exc()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Scan failed: {str(e)}",
        })
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))