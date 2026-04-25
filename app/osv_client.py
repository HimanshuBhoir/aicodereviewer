import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


async def lookup(package_name: str, version: str | None, ecosystem: str) -> list[dict]:
    payload: dict = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(OSV_QUERY_URL, json=payload)
        r.raise_for_status()
        return r.json().get("vulns", [])


def summarize_vuln(v: dict) -> dict:
    severity = "UNKNOWN"
    sev_list = v.get("severity") or []
    if sev_list:
        severity = sev_list[0].get("score", "UNKNOWN")
    for affected in v.get("affected", []):
        ds = affected.get("database_specific") or {}
        if ds.get("severity"):
            severity = ds["severity"]
            break

    fix_versions: list[str] = []
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    fix_versions.append(ev["fixed"])

    aliases = v.get("aliases", [])
    cve_ids = [a for a in aliases if a.startswith("CVE-")]
    summary = v.get("summary") or (v.get("details") or "")[:200]
    return {
        "id": v.get("id"),
        "cves": cve_ids,
        "severity": severity,
        "summary": summary,
        "fix_versions": sorted(set(fix_versions)),
    }
