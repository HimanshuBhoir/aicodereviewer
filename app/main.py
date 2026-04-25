import hashlib
import hmac
import logging

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from .config import settings
from .orchestrator import review_pull_request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("aicodereviewer")

app = FastAPI(title="CVE-Aware Code Review Agent")


@app.get("/")
async def root():
    return {"service": "aicodereviewer", "status": "ok"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


def _verify_signature(body: bytes, signature_header: str | None) -> bool:
    if not settings.github_webhook_secret:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    digest = hmac.new(settings.github_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature_header)


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    if not _verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="invalid signature")

    if x_github_event == "ping":
        return {"pong": True}
    if x_github_event != "pull_request":
        return {"skipped": True, "event": x_github_event}

    payload = await request.json()
    action = payload.get("action")
    if action not in {"opened", "reopened", "synchronize", "ready_for_review"}:
        return {"skipped": True, "action": action}

    pr = payload["pull_request"]
    repo = payload["repository"]
    owner = repo["owner"]["login"]
    repo_name = repo["name"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]

    background_tasks.add_task(review_pull_request, owner, repo_name, pr_number, head_sha)
    return {"queued": True, "owner": owner, "repo": repo_name, "pr": pr_number}
