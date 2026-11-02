"""거버넌스 화면 API — 감시자(P17) · 자산 현황(P18·P19) · LLM 게이트웨이 정규식 차단(P20).

app.py 가 register(app, h) 로 붙인다 — h 는 app.py 의 의존성(user·admin·superadmin·event·gitea_admin·publisher·REQUESTS·effective_verdict).
"""
import json
import os
import re
import time
from pathlib import Path

from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

DATA = Path(os.environ.get("KIT_DATA", "/data"))
STATIC = Path(__file__).parent / "static"
WATCHERS = DATA / "portal" / "watchers.json"
DLP = DATA / "portal" / "dlp.json"
DLP_LOG = DATA / "litellm" / "dlp.jsonl"
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$")
LEVELS = ("필수", "심화")

# 기본 정규식 — 개발자가 LLM 에 붙여 넣으면 막을 비밀값 모양. 값 자체는 기록하지 않는다.
DLP_DEFAULT = [
    {"id": "github-pat", "name": "GitHub 토큰 (ghp_·gho_·ghu_·ghs_·ghr_)", "regex": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"},
    {"id": "github-fine", "name": "GitHub 세분화 토큰 (github_pat_)", "regex": r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"},
    {"id": "atlassian-api", "name": "Atlassian(Confluence·Jira) Cloud API 토큰 (ATATT)", "regex": r"\bATATT3[A-Za-z0-9_\-=]{60,}"},
    {"id": "gitlab-pat", "name": "GitLab 토큰 (glpat-)", "regex": r"\bglpat-[A-Za-z0-9_\-]{20,}"},
    {"id": "aws-key", "name": "AWS 액세스 키 (AKIA·ASIA)", "regex": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"id": "slack", "name": "Slack 토큰 (xox?-)", "regex": r"\bxox[abprs]-[A-Za-z0-9-]{10,}"},
    {"id": "google-api", "name": "Google API 키 (AIza)", "regex": r"\bAIza[0-9A-Za-z_\-]{35}\b"},
    {"id": "anthropic", "name": "Anthropic API 키 (sk-ant-)", "regex": r"\bsk-ant-[A-Za-z0-9_\-]{20,}"},
    {"id": "openai", "name": "OpenAI API 키 (sk-proj-)", "regex": r"\bsk-proj-[A-Za-z0-9_\-]{20,}"},
    {"id": "private-key", "name": "개인 키 블록 (BEGIN … PRIVATE KEY)", "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
]


def _read(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return default


def _write(path, obj):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1))
    tmp.chmod(0o640)
    tmp.replace(path)


def load_dlp():
    d = _read(DLP, None)
    if d is None:
        d = {"version": 1, "patterns": [{**p, "enabled": True} for p in DLP_DEFAULT], "by": "kit", "at": time.time()}
        _write(DLP, d)
    return d


class Watcher(BaseModel):
    id: str
    name: str = ""
    kind: str = "image"          # builtin | image
    level: str = "필수"
    image: str = ""
    args: list[str] = []
    enabled: bool = True


class WatcherConf(BaseModel):
    watchers: list[Watcher]
    expected_version: int


class Pattern(BaseModel):
    id: str
    name: str
    regex: str
    enabled: bool = True


class DlpConf(BaseModel):
    patterns: list[Pattern]
    expected_version: int


def register(app, h):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gate-worker"))

    load_dlp()   # 처음 뜰 때 기본 패턴 파일을 만든다 — LiteLLM 훅이 첫 요청부터 막게

    def builtin_watchers():
        from watchers_conf import BUILTIN_WATCHERS   # 게이트와 같은 목록 하나
        return BUILTIN_WATCHERS

    # ── 감시자 (P17) ─────────────────────────────────────────────────
    @app.get("/api/watchers")
    def watchers_get(_=Depends(h.admin)):
        saved = _read(WATCHERS, {"version": 0, "watchers": []})
        by_id = {w["id"]: w for w in saved["watchers"]}
        out = [{**b, "level": by_id.get(b["id"], {}).get("level", b["level"]), "fixed": True} for b in builtin_watchers()]
        out += [w for w in saved["watchers"] if w.get("kind") == "image"]
        return {"version": saved.get("version", 0), "watchers": out, "by": saved.get("by"), "at": saved.get("at"), "levels": LEVELS}

    @app.put("/api/watchers")
    def watchers_put(body: WatcherConf, who=Depends(h.superadmin)):
        saved = _read(WATCHERS, {"version": 0, "watchers": []})
        if body.expected_version != saved.get("version", 0):
            raise HTTPException(409, "그 사이 다른 관리자가 바꿨습니다. 새로 고쳐 주세요")
        builtin = {b["id"] for b in builtin_watchers()}
        out, seen = [], set()
        for w in body.watchers:
            if w.level not in LEVELS:
                raise HTTPException(400, f"수준은 필수·심화 중 하나: {w.level}")
            if w.id in seen:
                raise HTTPException(400, f"같은 id 가 두 번: {w.id}")
            seen.add(w.id)
            if w.id in builtin:   # 기본 감시자는 끌 수 없다 — SkillSpector 등록이 하(최소) 기준
                out.append({"id": w.id, "kind": "builtin", "level": w.level})
                continue
            if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}", w.id) or not w.name.strip():
                raise HTTPException(400, "추가 감시자는 id(영문 소문자·숫자·-)와 이름이 필요합니다")
            if not IMAGE_RE.match(w.image):
                raise HTTPException(400, f"Docker 이미지 이름 형식이 아님: {w.image}")
            out.append({"id": w.id, "name": w.name.strip(), "kind": "image", "level": w.level, "image": w.image,
                        "args": [a for a in w.args if a], "enabled": w.enabled})
        missing = builtin - seen
        out += [{"id": i, "kind": "builtin", "level": "필수"} for i in sorted(missing)]
        new = {"version": saved.get("version", 0) + 1, "watchers": out, "by": who, "at": time.time()}
        _write(WATCHERS, new)
        h.event("watchers", who, version=new["version"], extra=[w["id"] for w in out if w["kind"] == "image"],
                levels={w["id"]: w["level"] for w in out})
        return watchers_get(who)

    @app.get("/admin/watchers")
    def watchers_page(_=Depends(h.admin)):
        return FileResponse(STATIC / "watchers.html")

    # ── 자산 현황 (P19) · 게시자 신원 (P18) ─────────────────────────────
    def all_repos():
        out, page = [], 1
        while True:
            got = json.loads(h.gitea_admin(f"/api/v1/repos/search?limit=50&page={page}&private=true")).get("data", [])
            out += got
            if len(got) < 50:
                return out
            page += 1

    def marketplace_syncs():
        """임직원 PC(IP)마다 마켓플레이스 저장소를 마지막으로 당긴 시각 — nginx 접속 기록에서(P11 PC별 제거 확인)."""
        import datetime
        path = f"/git/{h.publisher.MARKET_OWNER}/{h.publisher.MARKET_REPO}.git/"
        last = {}
        try:
            with open(DATA / "logs" / "nginx-access.log", errors="replace") as f:
                for line in f:
                    if path not in line or "git-upload-pack" not in line:
                        continue
                    m = re.match(r"(\S+) \S+ \S+ \[([^\]]+)\]", line)
                    if m:
                        t = datetime.datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp()
                        last[m.group(1)] = max(last.get(m.group(1), 0), t)
        except FileNotFoundError:
            pass
        return last

    @app.get("/api/assets")
    def assets(login: str = "", _=Depends(h.admin)):
        users = {u["login"]: {"login": u["login"], "name": u.get("full_name", ""), "email": u.get("email", "")}
                 for u in json.loads(h.gitea_admin("/api/v1/admin/users?limit=500"))}
        registry = h.publisher.load()
        by_repo_reg = {e["repo"]: (n, e) for n, e in registry.items()}
        reqs = [json.loads(f.read_text()) for f in sorted(h.REQUESTS.glob("*.json"))] if h.REQUESTS.exists() else []
        by_repo_req = {}
        for r in reqs:
            by_repo_req.setdefault(r["repo"], []).append(r)
        syncs = marketplace_syncs()
        rows = []
        for repo in all_repos():
            full = repo["full_name"]
            if full == f"{h.publisher.MARKET_OWNER}/{h.publisher.MARKET_REPO}":
                continue
            owner = repo["owner"]["login"]
            rq = sorted(by_repo_req.get(full, []), key=lambda r: r.get("created", 0))
            last = rq[-1] if rq else None
            reg_name, reg = by_repo_reg.get(full, (None, None))
            verdict = h.effective_verdict(last["result"]) if last and last.get("result") else None
            if reg and reg["status"] == "approved":
                stage, why = "배포 중", f"v{reg['version']} · 승인 {reg.get('approved_by')}"
            elif reg and reg["status"] == "revoked":
                after = sorted(ip for ip, t in syncs.items() if t >= reg.get("revoked_at", 0))
                before = sorted(ip for ip, t in syncs.items() if t < reg.get("revoked_at", 0))
                stage, why = "회수", (f"{reg.get('revoke_reason', '')} · 회수 뒤 다시 받아 지운 PC {len(after)}대"
                                      + (f" · 아직 안 받은 PC {len(before)}대({', '.join(before[:5])})" if before else ""))
            elif last and last.get("decision") == "rejected":
                stage, why = "탈락", f"반려 — {last.get('reason', '')}"
            elif last and last.get("status") in ("queued", "running"):
                stage, why = "검사 중", ""
            elif last and verdict in ("차단", "오류"):
                stage, why = "탈락", f"검사 {verdict} — 막는 항목 {sum(1 for f in last['result'].get('findings', []) if f['severity'] in ('critical', 'high') and f.get('level', '필수') == '필수')}개"
            elif last:
                stage, why = "승인 대기", f"검사 {verdict}"
            else:
                stage, why = "개발 중", "검사 요청 없음"
            history = [{"ts": r.get("created"), "what": f"검사 요청 {r['id']} — {h.effective_verdict(r['result']) if r.get('result') else r.get('status')}"
                        + (f" · {'승인' if r['decision'] == 'approved' else '반려'} {r.get('decided_by', '')}" if r.get("decision") in ("approved", "rejected") else "")}
                       for r in rq]
            if reg and reg.get("revoked_at"):
                history.append({"ts": reg["revoked_at"], "what": f"회수 {reg.get('revoked_by', '')} — {reg.get('revoke_reason', '')}"})
            ident = (reg or {}).get("publisher") or users.get(owner, {"login": owner})
            rows.append({"repo": full, "name": reg_name or (last or {}).get("name") or repo["name"], "owner": owner,
                         "owner_name": ident.get("name") or users.get(owner, {}).get("name", ""),
                         "owner_email": ident.get("email") or users.get(owner, {}).get("email", ""),
                         "stage": stage, "why": why, "version": (reg or {}).get("version"), "requests": len(rq),
                         "created": repo.get("created_at"), "updated": repo.get("updated_at"),
                         "last_activity": max([x["ts"] or 0 for x in history] or [0]) or None, "history": history})
        if login:
            rows = [r for r in rows if r["owner"] == login]
        stages = ("개발 중", "검사 중", "승인 대기", "탈락", "배포 중", "회수")
        people = {}
        for r in rows:
            p = people.setdefault(r["owner"], {"login": r["owner"], "name": r["owner_name"], "email": r["owner_email"], **{s: 0 for s in stages}})
            p[r["stage"]] += 1
        return {"marketplace_pcs": [{"ip": ip, "last": t} for ip, t in sorted(syncs.items(), key=lambda x: -x[1])],
                "rows": sorted(rows, key=lambda r: (stages.index(r["stage"]), r["repo"])), "counts": {s: sum(r["stage"] == s for r in rows) for s in stages},
                "people": sorted(people.values(), key=lambda p: p["login"]), "stages": stages}

    @app.get("/admin/assets")
    def assets_page(_=Depends(h.admin)):
        return FileResponse(STATIC / "assets.html")

    # ── LLM 게이트웨이 정규식 차단 (P20) ─────────────────────────────────
    @app.get("/api/dlp")
    def dlp_get(_=Depends(h.admin)):
        d = load_dlp()
        log = []
        try:
            for line in DLP_LOG.read_text().splitlines()[-200:]:
                log.append(json.loads(line))
        except (FileNotFoundError, ValueError):
            pass
        return {**d, "log": log[::-1]}

    @app.put("/api/dlp")
    def dlp_put(body: DlpConf, who=Depends(h.superadmin)):
        cur = load_dlp()
        if body.expected_version != cur["version"]:
            raise HTTPException(409, "그 사이 다른 관리자가 바꿨습니다. 새로 고쳐 주세요")
        pats, seen = [], set()
        for p in body.patterns:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", p.id) or p.id in seen or not p.name.strip():
                raise HTTPException(400, f"id(영문 소문자·숫자·-, 겹치지 않게)와 이름이 필요합니다: {p.id}")
            if len(p.regex) > 500:
                raise HTTPException(400, f"정규식이 너무 깁니다: {p.id}")
            try:
                re.compile(p.regex)
            except re.error as e:
                raise HTTPException(400, f"정규식 오류 ({p.id}): {e}")
            seen.add(p.id)
            pats.append({"id": p.id, "name": p.name.strip(), "regex": p.regex, "enabled": p.enabled})
        new = {"version": cur["version"] + 1, "patterns": pats, "by": who, "at": time.time()}
        _write(DLP, new)
        h.event("dlp", who, version=new["version"], patterns=len(pats), enabled=sum(p["enabled"] for p in pats))
        return dlp_get(who)

    @app.get("/admin/dlp")
    def dlp_page(_=Depends(h.admin)):
        return FileResponse(STATIC / "dlp.html")
