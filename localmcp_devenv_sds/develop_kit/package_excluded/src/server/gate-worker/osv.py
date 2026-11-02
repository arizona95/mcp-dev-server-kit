"""osv.dev 실조회 — requirements.txt 의 고정 버전(==)을 PyPI 생태계로 묻는다. 바깥은 HTTPS_PROXY(squid) 로 나간다."""
import json
import re
import urllib.request

API = "https://api.osv.dev/v1"
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)")


def pinned(requirements_text):
    """[(줄 번호, 패키지, 버전)] — == 로 고정된 것만. 고정 안 된 줄은 따로 돌려준다."""
    pins, loose = [], []
    for n, line in enumerate(requirements_text.splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith("-"):
            continue
        m = REQ_LINE.match(s)
        (pins if m else loose).append((n, m.group(1).lower(), m.group(2)) if m else (n, s))
    return pins, loose


def _post(path, body):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _get(path):
    with urllib.request.urlopen(API + path, timeout=20) as r:
        return json.loads(r.read())


def fixed_versions(vuln, package):
    """advisory 의 affected[].ranges[].events[].fixed 중 이 패키지 것."""
    out = []
    for a in vuln.get("affected", []):
        if a.get("package", {}).get("name", "").lower() != package or a.get("package", {}).get("ecosystem") != "PyPI":
            continue
        for r in a.get("ranges", []):
            out += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return out


def _version_key(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def query(requirements_text):
    pins, loose = pinned(requirements_text)
    if not pins:
        return [], loose
    res = _post("/querybatch", {"queries": [{"package": {"name": p, "ecosystem": "PyPI"}, "version": v} for _, p, v in pins]})
    hits = []
    for (line, pkg, ver), r in zip(pins, res.get("results", [])):
        for v in r.get("vulns", []):
            detail = _get(f"/vulns/{v['id']}")
            fixed = fixed_versions(detail, pkg)
            later = sorted((f for f in fixed if _version_key(f) > _version_key(ver)), key=_version_key)
            hits.append({"line": line, "package": pkg, "version": ver, "id": detail["id"],
                         "aliases": detail.get("aliases", []), "summary": detail.get("summary", ""),
                         "details": detail.get("details", "")[:1200], "fixed": later[0] if later else None,
                         "all_fixed": fixed})
    return hits, loose
