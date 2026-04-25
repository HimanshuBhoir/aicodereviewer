import json
import re

REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]+\])?\s*([<>=!~]=?|===)?\s*([A-Za-z0-9_.\-+*]*)"
)


def parse_requirements_txt(content: str) -> list[dict]:
    deps: list[dict] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = REQUIREMENT_RE.match(line)
        if not m:
            continue
        name, _extras, op, version = m.group(1), m.group(2), m.group(3), m.group(4)
        pinned = op in ("==", "===") and version
        deps.append(
            {
                "name": name,
                "version": version if pinned else None,
                "ecosystem": "PyPI",
            }
        )
    return deps


def parse_package_json(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps: list[dict] = []
    for section in ("dependencies", "devDependencies"):
        for name, raw_version in (data.get(section) or {}).items():
            cleaned = re.sub(r"^[\^~>=<\s]+", "", str(raw_version)).strip()
            deps.append(
                {
                    "name": name,
                    "version": cleaned or None,
                    "ecosystem": "npm",
                }
            )
    return deps


def detect_and_parse(path: str, content: str) -> list[dict]:
    p = path.lower()
    if p.endswith("requirements.txt"):
        return parse_requirements_txt(content)
    if p.endswith("package.json"):
        return parse_package_json(content)
    return []
