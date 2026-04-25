import json

import httpx

from .config import settings

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "title": {"type": "string"},
                    "explanation": {"type": "string"},
                    "suggestion": {"type": "string"},
                },
                "required": ["file", "severity", "category", "title", "explanation"],
                "propertyOrdering": [
                    "file",
                    "severity",
                    "category",
                    "title",
                    "explanation",
                    "suggestion",
                ],
            },
        },
    },
    "required": ["summary", "issues"],
    "propertyOrdering": ["summary", "issues"],
}

SYSTEM_PROMPT = (
    "You are a senior code reviewer. Review the provided file diffs for a pull request and flag real issues only. "
    "Cover: security anti-patterns (hardcoded secrets, SQL/command injection, unsafe deserialization, weak crypto, "
    "missing authn/authz, SSRF, path traversal), code quality (unhandled errors, dead code, missing input validation, "
    "complexity), logic bugs and race conditions, and bad practices (broad except, eval/exec, mutable default args). "
    "Severity must be one of CRITICAL, HIGH, MEDIUM, LOW. Category must be one of security, bug, quality, style. "
    "Do not invent issues. If a diff is fine, return an empty issues array and a short positive summary."
)


async def review_files(files: list[dict]) -> dict:
    if not settings.gemini_api_key:
        return {"summary": "AI review skipped: GEMINI_API_KEY not set.", "issues": []}
    if not files:
        return {"summary": "No reviewable code changes.", "issues": []}

    blocks = []
    for f in files:
        block = (
            f"FILE: {f['path']}\n"
            f"STATUS: {f.get('status')}\n"
            f"--- DIFF ---\n{f.get('patch') or '[no patch]'}"
        )
        if f.get("content"):
            block += f"\n--- CURRENT CONTENT ---\n{f['content']}"
        blocks.append(block)
    user_text = "\n\n".join(blocks)

    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {
            "response_mime_type": "application/json",
            "response_schema": REVIEW_SCHEMA,
        },
    }
    url = GEMINI_URL.format(model=settings.gemini_model)
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(url, params={"key": settings.gemini_api_key}, json=body)
        r.raise_for_status()
        data = r.json()

    try:
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(text)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return {"summary": f"AI review parse error: {e}", "issues": []}
