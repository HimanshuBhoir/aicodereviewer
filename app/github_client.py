import httpx

from .config import settings

GITHUB_API = "https://api.github.com"


def _headers(accept: str = "application/vnd.github+json") -> dict:
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aicodereviewer",
    }


async def get_pr_files(owner: str, repo: str, pr_number: int) -> list[dict]:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files",
            headers=_headers(),
            params={"per_page": 100},
        )
        r.raise_for_status()
        return r.json()


async def get_file_content(owner: str, repo: str, path: str, ref: str) -> str | None:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
            headers=_headers("application/vnd.github.raw"),
            params={"ref": ref},
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.text


async def post_pr_comment(owner: str, repo: str, pr_number: int, body: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{pr_number}/comments",
            headers=_headers(),
            json={"body": body},
        )
        r.raise_for_status()
        return r.json()
