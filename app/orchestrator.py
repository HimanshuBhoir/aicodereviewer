import logging

from .ai_reviewer import review_files
from .config import settings
from .deps_parser import detect_and_parse
from .github_client import get_file_content, get_pr_files, post_pr_comment
from .osv_client import lookup, summarize_vuln

log = logging.getLogger("aicodereviewer.orchestrator")

REVIEWABLE_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".rs", ".php")
MANIFEST_SUFFIXES = ("requirements.txt", "package.json")


async def review_pull_request(owner: str, repo: str, pr_number: int, head_sha: str) -> None:
    log.info("review start %s/%s#%s sha=%s", owner, repo, pr_number, head_sha)
    try:
        files = await get_pr_files(owner, repo, pr_number)
    except Exception as e:
        log.exception("fetch PR files failed: %s", e)
        return

    files = files[: settings.max_files_to_review]
    cve_findings: list[dict] = []
    unpinned: list[dict] = []
    review_payload: list[dict] = []

    for f in files:
        path = f["filename"]
        status = f.get("status")
        patch = f.get("patch")

        if status != "removed" and path.lower().endswith(MANIFEST_SUFFIXES):
            content = await get_file_content(owner, repo, path, head_sha)
            if content:
                for d in detect_and_parse(path, content):
                    if not d["version"]:
                        unpinned.append({"name": d["name"], "ecosystem": d["ecosystem"], "file": path})
                        continue
                    try:
                        vulns = await lookup(d["name"], d["version"], d["ecosystem"])
                    except Exception as e:
                        log.warning("OSV lookup failed for %s@%s: %s", d["name"], d["version"], e)
                        continue
                    for v in vulns:
                        cve_findings.append(
                            {
                                "package": d["name"],
                                "version": d["version"],
                                "ecosystem": d["ecosystem"],
                                "file": path,
                                **summarize_vuln(v),
                            }
                        )

        if patch and path.lower().endswith(REVIEWABLE_EXTS):
            content = await get_file_content(owner, repo, path, head_sha) if status != "removed" else None
            review_payload.append(
                {
                    "path": path,
                    "status": status,
                    "patch": patch[: settings.max_file_bytes],
                    "content": (content or "")[: settings.max_file_bytes],
                }
            )

    cve_findings = _dedupe_cves(cve_findings)

    try:
        review = await review_files(review_payload)
    except Exception as e:
        log.exception("AI review failed: %s", e)
        review = {"summary": f"AI review failed: {e}", "issues": []}

    body = format_comment(review, cve_findings, unpinned)
    try:
        await post_pr_comment(owner, repo, pr_number, body)
        log.info("posted review on %s/%s#%s", owner, repo, pr_number)
    except Exception as e:
        log.exception("post comment failed: %s", e)


def _dedupe_cves(findings: list[dict]) -> list[dict]:
    """Collapse duplicate advisories (e.g. GHSA + PYSEC for same CVE) per package."""
    by_key: dict[tuple, dict] = {}
    for f in findings:
        cve = (f.get("cves") or [None])[0]
        key = (f["package"], f["ecosystem"], cve or f.get("id"))
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
            continue
        if existing.get("severity") in (None, "", "UNKNOWN") and f.get("severity") not in (None, "", "UNKNOWN"):
            by_key[key] = f
    return list(by_key.values())


def format_comment(review: dict, cves: list[dict], unpinned: list[dict] | None = None) -> str:
    lines: list[str] = ["## CVE-Aware Code Review", ""]
    summary = (review.get("summary") or "").strip()
    if summary:
        lines.extend([f"_{summary}_", ""])

    lines.append("### Vulnerable dependencies")
    if cves:
        lines.append("")
        lines.append("| Package | Version | Severity | Advisory | Fix versions |")
        lines.append("| --- | --- | --- | --- | --- |")
        for c in cves:
            advisory = ", ".join(c.get("cves") or []) or c.get("id") or ""
            fix = ", ".join(c.get("fix_versions") or []) or "—"
            lines.append(
                f"| `{c['package']}` | {c.get('version') or '?'} | {c.get('severity')} | {advisory} | {fix} |"
            )
        lines.append("")
        for c in cves:
            if c.get("summary"):
                advisory = ", ".join(c.get("cves") or []) or c.get("id") or ""
                lines.append(f"- **{c['package']}** ({advisory}): {c['summary']}")
        lines.append("")
    else:
        lines.append("No vulnerable dependencies detected (or no manifest changes in this PR).")
        lines.append("")

    if unpinned:
        lines.append("### Unpinned dependencies (skipped)")
        lines.append("")
        lines.append("These packages had no exact version (`==`) so OSV lookup was skipped to avoid false positives. Pin them or add a lockfile for accurate CVE checks.")
        lines.append("")
        for u in unpinned:
            lines.append(f"- `{u['name']}` ({u['ecosystem']}) in `{u['file']}`")
        lines.append("")

    issues = review.get("issues") or []
    lines.append(f"### Code review findings ({len(issues)})")
    if issues:
        lines.append("")
        for i in issues:
            sev = i.get("severity", "?")
            cat = i.get("category", "?")
            title = i.get("title", "")
            file = i.get("file", "")
            lines.append(f"- **[{sev}] [{cat}]** `{file}` — {title}")
            if i.get("explanation"):
                lines.append(f"  - {i['explanation']}")
            if i.get("suggestion"):
                lines.append(f"  - Suggested fix: {i['suggestion']}")
        lines.append("")
    else:
        lines.append("No code quality issues detected.")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by aicodereviewer · CVE data: OSV.dev · Review: Gemini_")
    return "\n".join(lines)
