"""포털 — 로그인은 Gitea 계정(OAuth2). 지금은 관리자 egress 통제 패널. 업로드·승인·다운로드 화면은 같은 앱에 더한다."""
import json
import re
import os
import secrets
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "egress-proxy"))
import egress  # noqa: E402
import selftest  # noqa: E402

DATA = Path(os.environ.get("KIT_DATA", "/data"))
PUBLIC = os.environ["KIT_PUBLIC_URL"].rstrip("/")
GITEA = "http://127.0.0.1:3000"
OAUTH_FILE = DATA / "portal" / "oauth.json"
ACCESS_LOG = f"{egress.EGRESS}/access.log"


def session_secret():
    f = DATA / "portal" / "session_secret"
    if not f.exists():
        f.write_text(secrets.token_urlsafe(48))
        f.chmod(0o600)
    return f.read_text().strip()


app = FastAPI(title="mcp-dev-server-kit portal")
app.add_middleware(SessionMiddleware, secret_key=session_secret(), session_cookie="kit_session",
                   same_site="lax", https_only=PUBLIC.startswith("https://"), max_age=8 * 3600)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
def to_login(request: Request, _):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "로그인이 필요합니다"}, status_code=401)
    nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
    return RedirectResponse("/login?next=" + urllib.parse.quote(nxt))


ROLES = DATA / "portal" / "roles.json"
ROLE_LABEL = {"super": "주관리자", "admin": "관리자", "dev": "개발자"}


def load_roles():
    try:
        return json.loads(ROLES.read_text())
    except FileNotFoundError:
        return {"admins": {}, "requests": {}}


def save_roles(r):
    tmp = ROLES.with_suffix(".tmp")
    tmp.write_text(json.dumps(r, ensure_ascii=False, indent=1))
    tmp.replace(ROLES)


def role_of(login, gitea_admin):
    """주관리자 = Gitea 사이트 관리자 · 관리자 = 주관리자가 허용한 계정 · 그 밖 = 개발자. 요청마다 다시 본다."""
    if gitea_admin:
        return "super"
    return "admin" if login in load_roles()["admins"] else "dev"


def user(request: Request):
    u = request.session.get("user")
    if not u:
        raise LoginRequired()
    role = role_of(u["login"], u.get("gitea_admin", u.get("is_admin")))
    return {**u, "role": role, "role_label": ROLE_LABEL[role], "is_admin": role in ("super", "admin"), "is_super": role == "super",
            "ip": request.headers.get("x-real-ip") or (request.client.host if request.client else "")}


def admin(u=Depends(user)):
    """관리자 이상 (관리자 · 주관리자)."""
    if not u["is_admin"]:
        raise HTTPException(403, "관리자만 볼 수 있습니다")
    return u["login"]


def superadmin(u=Depends(user)):
    if not u["is_super"]:
        raise HTTPException(403, "주관리자만 할 수 있습니다")
    return u["login"]


def oauth():
    return json.loads(OAUTH_FILE.read_text())


@app.get("/login")
def login(request: Request, next: str = "/"):
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    request.session["next"] = next if next.startswith("/") and not next.startswith("//") else "/"
    q = urllib.parse.urlencode({"client_id": oauth()["client_id"], "redirect_uri": oauth()["redirect"],
                                "response_type": "code", "state": state})
    return RedirectResponse(f"{PUBLIC}/git/login/oauth/authorize?{q}")


@app.get("/auth/callback")
def callback(request: Request, code: str, state: str):
    if not secrets.compare_digest(state, request.session.pop("oauth_state", "")):
        raise HTTPException(400, "로그인 요청이 맞지 않습니다. 다시 로그인해 주세요")
    o = oauth()
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": o["redirect"],
                                   "client_id": o["client_id"], "client_secret": o["client_secret"]}).encode()
    with urllib.request.urlopen(urllib.request.Request(f"{GITEA}/login/oauth/access_token", data=form,
                                                       headers={"Accept": "application/json"}), timeout=10) as r:
        token = json.loads(r.read())["access_token"]
    with urllib.request.urlopen(urllib.request.Request(f"{GITEA}/api/v1/user",
                                                       headers={"Authorization": f"Bearer {token}"}), timeout=10) as r:
        me = json.loads(r.read())
    # 게시자 신원(P18): Gitea(= SSO 를 붙이면 회사 계정)의 이름·이메일을 함께 둔다
    request.session["user"] = {"login": me["login"], "gitea_admin": bool(me.get("is_admin")),
                               "email": me.get("email", ""), "full_name": me.get("full_name", "")}
    event("login", me["login"], admin=bool(me.get("is_admin")))
    return RedirectResponse(request.session.pop("next", "/"))


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(f"{PUBLIC}/git/user/logout")


@app.get("/api/me")
def me(u=Depends(user)):
    pending = load_roles()["requests"].get(u["login"])
    return {**u, "admin_request": pending}


@app.get("/")
def home(u=Depends(user)):
    return RedirectResponse("/mcp" if u["is_admin"] else "/new")


class Rule(BaseModel):
    host: str
    port: int = 443
    reason: str


def read_changes(limit=50):
    try:
        lines = Path(egress.CHANGES).read_text().splitlines()
    except FileNotFoundError:
        return []
    return [json.loads(x) for x in lines[-limit:]][::-1]


def parse_access(line):
    # kit 로그형식: 시각 출발지 결과/코드 메소드 대상
    parts = line.split()
    if len(parts) < 5:
        return None
    result, _, code = parts[2].partition("/")
    return {"ts": float(parts[0]), "src": parts[1], "result": result, "code": code,
            "method": parts[3], "target": parts[4], "allowed": "DENIED" not in result}


@app.get("/admin/egress")
def egress_page(_=Depends(admin)):
    return FileResponse(Path(__file__).parent / "static" / "egress.html")


@app.get("/api/egress")
def egress_state(_=Depends(admin)):
    try:
        status = egress.request("status")
    except OSError as e:
        status = {"ok": False, "error": str(e)}
    return {"rules": egress.all_rules(), "changes": read_changes(),
            "direct_blocked": status.get("direct_blocked"), "blocked_seen": status.get("blocked_seen", [])}


@app.get("/api/egress/log")
def egress_log(limit: int = 200, _=Depends(admin)):
    try:
        lines = Path(ACCESS_LOG).read_text().splitlines()[-limit:]
    except FileNotFoundError:
        lines = []
    return [e for e in map(parse_access, lines) if e][::-1]


def save_and_apply(extra, action, rule, who):
    Path(egress.EXTRA).write_text(json.dumps(extra, ensure_ascii=False, indent=1))
    reply = egress.request("apply")
    if not reply.get("ok"):
        raise HTTPException(500, reply.get("error", "적용 실패"))
    egress.log_change(action, rule, who)
    return reply


@app.post("/api/egress")
def add_rule(rule: Rule, who=Depends(superadmin)):
    r = {"host": rule.host.strip().lower(), "port": rule.port, "reason": rule.reason.strip()}
    try:
        egress.validate(r)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not r["reason"]:
        raise HTTPException(400, "열어 주는 이유를 적어 주세요")
    if any(x["host"] == r["host"] and x["port"] == r["port"] for x in egress.all_rules()):
        raise HTTPException(409, "이미 허용목록에 있습니다")
    return save_and_apply(egress.load_extra() + [r], "add", r, who)


@app.delete("/api/egress/{host}/{port}")
def remove_rule(host: str, port: int, who=Depends(superadmin)):
    if any(x["host"] == host and x["port"] == port for x in egress.builtin_rules()):
        raise HTTPException(400, "기본 줄은 gate.env 에서 바꿉니다")
    extra = egress.load_extra()
    gone = [x for x in extra if x["host"] == host and x["port"] == port]
    if not gone:
        raise HTTPException(404, "허용목록에 없습니다")
    return save_and_apply([x for x in extra if x not in gone], "remove", gone[0], who)


@app.post("/api/egress/selftest")
def run_selftest(_=Depends(admin)):
    return selftest.run(egress.all_rules())


# ── 개인 LLM 키 · 다운로드 ─────────────────────────────────────────────
DEVKIT = Path(os.environ.get("KIT_DEVKIT", "/opt/kit/devkit"))
TOKENS = DATA / "portal" / "tokens.json"
CA_FILE = Path("/etc/kit/tls/ca.pem")


def goose_files():
    """VERSION 파일: OS → (파일 이름, sha256)."""
    files = {}
    for line in (DEVKIT / "hosts" / "goose" / "VERSION").read_text().splitlines():
        if "=" in line and not line.startswith("#") and not line.startswith("version"):
            os_name, rest = line.split("=", 1)
            name, digest = rest.split()
            files[os_name] = (name, digest.removeprefix("sha256:"))
    return files


def load_tokens():
    try:
        return json.loads(TOKENS.read_text())
    except FileNotFoundError:
        return {}


def token_hash(t):
    import hashlib
    return hashlib.sha256(t.encode()).hexdigest()


def token_user(request: Request, kind=("run",)):
    """Authorization: Bearer <실행 토큰·설치 코드> → 로그인 이름. 없거나 지났거나 종류가 다르면 None."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    entry = load_tokens().get(token_hash(auth[7:].strip()))
    if not entry or entry.get("exp", float("inf")) < __import__("time").time():
        return None
    if kind and entry.get("kind", "run") not in kind:
        return None
    return entry["login"]


# 개인 PC 에 키를 저장하지 않는다(P7): 오래 쓰는 개인 키 대신 ① 설치용 내려받기 코드(30분, 파일 내려받기만)
# ② 실행 토큰(mcp-test 가 실행마다 브라우저 로그인으로 받음, 1시간, 메모리에만). 서버는 해시만 둔다.
RUN_TTL = int(os.environ.get("KIT_RUN_TOKEN_TTL", "3600"))
DL_TTL = 1800


def mint(login, kind, ttl, **extra):
    import time as _t
    now = _t.time()
    tokens = {h: e for h, e in load_tokens().items() if e.get("exp", 0) > now}   # 지난 것은 정리
    t = ("kitrun-" if kind == "run" else "kitdl-") + secrets.token_urlsafe(32)
    tokens[token_hash(t)] = {"login": login, "kind": kind, "created": now, "exp": now + ttl, **extra}
    tmp = TOKENS.with_suffix(".tmp")
    tmp.write_text(json.dumps(tokens))
    tmp.chmod(0o600)
    tmp.replace(TOKENS)
    return t


@app.post("/api/dlcode")
def issue_dlcode(u=Depends(user)):
    """설치 명령에 붙일 내려받기 코드 — 30분 동안 설치 파일만 받는다(LLM·정책·비밀값에는 못 씀). PC 에 저장되지 않는다."""
    event("dlcode", u["login"])
    return {"code": mint(u["login"], "download", DL_TTL), "ttl": DL_TTL}


@app.get("/cli/login")
def cli_login(port: int, state: str, u=Depends(user)):
    """mcp-test 가 여는 브라우저 로그인 — 실행 토큰을 만들어 PC 의 127.0.0.1:<port> 로 돌려준다(그 프로세스 메모리에만)."""
    if not 1024 <= port <= 65535 or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", state):
        raise HTTPException(400, "잘못된 요청")
    t = mint(u["login"], "run", RUN_TTL, ip=u["ip"])
    event("run_token", u["login"], ip=u["ip"])
    # 주소(쿼리)로 넘기면 브라우저 방문 기록에 남는다 — 자동 제출 폼(POST 본문)으로 PC 의 mcp-test 에 넘긴다
    from fastapi.responses import HTMLResponse
    return HTMLResponse(f"""<!doctype html><meta charset="utf-8"><title>MCP Dev Kit</title>
<body onload="document.forms[0].submit()" style="font:16px sans-serif;margin:40px">mcp-test 로 넘기는 중…
<form method="post" action="http://127.0.0.1:{port}/cb"><input type="hidden" name="state" value="{state}"><input type="hidden" name="token" value="{t}"></form></body>""",
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


class TokenRevoke(BaseModel):
    login: str = ""
    reason: str = ""


@app.post("/api/tokens/revoke")
def revoke_tokens(body: TokenRevoke, u=Depends(user)):
    """즉시 중단(kill switch): 그 사람의 실행 토큰·내려받기 코드를 모두 지운다 → 다음 LLM·정책·비밀값 요청부터 거부."""
    login = body.login or u["login"]
    if login != u["login"] and not u["is_admin"]:
        raise HTTPException(403)
    tokens = load_tokens()
    left = {h: e for h, e in tokens.items() if e["login"] != login}
    TOKENS.write_text(json.dumps(left))
    event("token_revoke", u["login"], target=login, n=len(tokens) - len(left), reason=body.reason)
    return {"revoked": len(tokens) - len(left)}


@app.get("/api/token")
def token_info(u=Depends(user)):
    import time as _t
    mine = [e for e in load_tokens().values() if e["login"] == u["login"] and e.get("exp", 0) > _t.time()]
    return {"active": len([e for e in mine if e.get("kind") == "run"]), "ttl": RUN_TTL}


@app.get("/_auth/llm")
def auth_llm(request: Request):
    """nginx auth_request: /llm/ 요청마다 실행 토큰을 확인한다."""
    login = token_user(request)
    if not login:
        return JSONResponse({"detail": "실행 토큰이 없거나 지났습니다 — mcp-test 를 다시 실행해 로그인하세요"}, status_code=401)
    return JSONResponse({"login": login}, headers={"X-Kit-User": login})


def render_installer(name, os_name):
    file, digest = goose_files()[os_name]
    ca = CA_FILE.read_text().strip() if CA_FILE.exists() else ""
    text = (DEVKIT / "installer" / name).read_text()
    import hashlib
    srt = DEVKIT / "hosts" / "srt" / "srt-bundle.tgz"
    mjs = DEVKIT / "installer" / "mcp-test.mjs"
    shim = DEVKIT / "hosts" / "pyshim" / "sitecustomize.py"
    gate = DEVKIT / "installer" / "mcp-gate.mjs"
    for k, v in {"PUBLIC": PUBLIC, "GOOSE_FILE": file, "GOOSE_SHA256": digest, "CA_PEM": ca,
                 "SRT_SHA256": hashlib.sha256(srt.read_bytes()).hexdigest() if srt.exists() else "",
                 "MJS_SHA256": hashlib.sha256(mjs.read_bytes()).hexdigest(),
                 "PYSHIM_SHA256": hashlib.sha256(shim.read_bytes()).hexdigest(),
                 "GATE_SHA256": hashlib.sha256(gate.read_bytes()).hexdigest()}.items():
        text = text.replace("{{" + k + "}}", v)
    return text


@app.get("/download/install.sh")
def install_sh():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(render_installer("install.sh", "linux-x64"))


@app.get("/download/install.ps1")
def install_ps1():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(render_installer("install.ps1", "windows-x64"))


@app.get("/download/files/{name}")
def download_file(name: str, request: Request):
    """설치 파일 — 로그인 세션이나 설치 코드가 있어야 받는다."""
    if not (request.session.get("user") or token_user(request, kind=("download", "run"))):
        raise HTTPException(401, "로그인하거나 설치 코드를 붙여 주세요")
    for os_name, (file, _) in goose_files().items():
        if name == file:
            return FileResponse(DEVKIT / "hosts" / "goose" / os_name / file, filename=file)
    if name == "bwrap-userns.apparmor":   # 리눅스 IT 사전 준비 — Ubuntu 23.10+ 에서 bubblewrap 에 userns 허용
        return FileResponse(DEVKIT / "policies" / "linux" / name, filename=name)
    if name == "applocker-goose.ps1":    # 윈도우 IT — goose 는 샌드박스 안에서만(AppLocker)
        return FileResponse(DEVKIT / "policies" / "windows" / name, filename=name)
    if name == "sitecustomize.py":   # 윈도우 srt 샌드박스 안 파이썬 보정 (루프백 허용 범위 socketpair)
        return FileResponse(DEVKIT / "hosts" / "pyshim" / name, filename=name)
    if name in ("srt-bundle.tgz", "mcp-test.mjs", "mcp-gate.mjs"):
        return FileResponse(DEVKIT / ("hosts/srt" if name.endswith(".tgz") else "installer") / name, filename=name)
    raise HTTPException(404)


@app.get("/api/devkit/identity")
def devkit_identity(request: Request):
    """설치 스크립트가 git 커밋 이름·이메일을 사내 계정 그대로 맞출 때 쓴다(게시자 신원 P18)."""
    login = token_user(request, kind=("download", "run"))
    if not login:
        raise HTTPException(401)
    u = json.loads(gitea_admin(f"/api/v1/users/{urllib.parse.quote(login)}"))
    return {"login": login, "name": u.get("full_name") or login, "email": u.get("email") or f"{login}@users.noreply"}


@app.get("/api/download")
def download_info(u=Depends(user)):
    files = goose_files()
    return {"public": PUBLIC, "goose": {k: {"file": f, "sha256": d} for k, (f, d) in files.items()},
            "version": next(l.split("=")[1] for l in (DEVKIT / "hosts/goose/VERSION").read_text().splitlines() if l.startswith("version=")),
            "ca": CA_FILE.exists()}


@app.get("/download")
def download_page(u=Depends(user)):
    return FileResponse(Path(__file__).parent / "static" / "download.html")


# ── MCP 등록 요청 · 검사 결과 · 승인 · 레지스트리 ─────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "publisher"))
import publisher  # noqa: E402

REQUESTS = DATA / "registry" / "requests"


def gitea_admin(path):
    import base64
    auth = base64.b64encode(f"{os.environ.get('KIT_ADMIN_USER', 'kitadmin')}:{os.environ['PORTAL_ADMIN_PASSWORD']}".encode()).decode()
    req = urllib.request.Request(GITEA + path, headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def load_request(rid):
    f = REQUESTS / f"{rid}.json"
    if not re.fullmatch(r"[0-9a-z-]+", rid) or not f.exists():
        raise HTTPException(404, "요청이 없습니다")
    return json.loads(f.read_text())


def save_request(req):
    f = REQUESTS / f"{req['id']}.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(req, ensure_ascii=False, indent=1))
    tmp.replace(f)


def visible(req, u):
    return u["is_admin"] or req["submitter"] == u["login"]


class NewRequest(BaseModel):
    repo: str
    ref: str = "main"


@app.get("/api/repos")
def my_repos(u=Depends(user)):
    repos = json.loads(gitea_admin(f"/api/v1/users/{urllib.parse.quote(u['login'])}/repos?limit=50"))
    return [{"full_name": r["full_name"], "default_branch": r["default_branch"]} for r in repos]


@app.post("/api/requests")
def new_request(body: NewRequest, u=Depends(user)):
    owner = body.repo.split("/", 1)[0]
    if owner != u["login"] and not u["is_admin"]:
        raise HTTPException(403, "내 저장소만 요청할 수 있습니다")
    try:
        manifest = json.loads(gitea_admin(f"/api/v1/repos/{body.repo}/raw/kit-mcp.json?ref={urllib.parse.quote(body.ref)}"))
    except Exception:
        raise HTTPException(400, f"{body.repo}@{body.ref} 최상위에 kit-mcp.json 이 없습니다")
    import time as _t
    name = manifest.get("name", body.repo.split("/")[-1])
    owner_of = publisher.load().get(name, {}).get("repo", "").split("/", 1)[0]
    if owner_of and owner_of != owner:   # 개발자 사이 침해 방지(P15): 남이 배포한 이름으로 올려 덮어쓰지 못한다
        raise HTTPException(403, f"'{name}' 은 {owner_of} 의 MCP 이름입니다. kit-mcp.json 의 name 을 바꿔 주세요")
    rid = _t.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    REQUESTS.mkdir(parents=True, exist_ok=True)
    req = {"id": rid, "repo": body.repo, "ref": body.ref, "name": name,
           "submitter": u["login"], "submitter_name": u.get("full_name", ""), "submitter_email": u.get("email", ""), "created": _t.time(), "status": "queued", "decision": "pending"}
    save_request(req)
    event("request", u["login"], request=rid, repo=body.repo)
    return req


@app.get("/api/requests")
def list_requests(u=Depends(user)):
    out = []
    for f in sorted(REQUESTS.glob("*.json"), reverse=True) if REQUESTS.exists() else []:
        r = json.loads(f.read_text())
        if visible(r, u):
            res = r.get("result") or {}
            out.append({k: r.get(k) for k in ("id", "repo", "ref", "name", "submitter", "created", "status", "decision")} |
                       {"verdict": effective_verdict(res) if res else None, "raw_verdict": res.get("verdict"), "findings": len(res.get("findings", [])),
                        "flags": sorted({fl for t in (res.get("review") or {}).get("tools", []) for fl in t["flags"]})})
    return out


@app.get("/api/requests/{rid}")
def get_request(rid: str, u=Depends(user)):
    r = load_request(rid)
    if not visible(r, u):
        raise HTTPException(403)
    if r.get("result"):
        r["result"]["effective_verdict"] = effective_verdict(r["result"])
    return r


class Decision(BaseModel):
    action: str
    reason: str = ""


@app.post("/api/requests/{rid}/decision")
def decide(rid: str, d: Decision, who=Depends(admin)):
    import time as _t
    r = load_request(rid)
    if r["status"] != "done":
        raise HTTPException(409, "검사가 끝나지 않았습니다")
    verdict = effective_verdict(r.get("result") or {})
    if d.action == "approve" and r["submitter"] == who:   # P5: 만든 사람과 승인하는 사람을 나눈다
        raise HTTPException(403, "자기가 올린 MCP 는 다른 관리자가 승인해야 합니다")
    if d.action == "approve":
        if verdict in ("차단", "오류"):
            raise HTTPException(409, f"검사 결과가 '{verdict}' 이라 승인할 수 없습니다 (막는 항목의 소명이 모두 허용되면 승인할 수 있습니다)")
        try:
            publisher.approve(r, who, identity={"login": r["submitter"], "name": r.get("submitter_name", ""),
                                                "email": r.get("submitter_email", "")})
        except ValueError as e:
            raise HTTPException(409, str(e))
        r["decision"] = "approved"
    elif d.action == "reject":
        if not d.reason.strip():
            raise HTTPException(400, "반려 사유를 적어 주세요")
        r["decision"] = "rejected"
    else:
        raise HTTPException(400)
    r.update(decided_by=who, decided_at=_t.time(), reason=d.reason.strip())
    save_request(r)
    event("decision", who, request=rid, action=d.action)
    return r


@app.get("/api/registry")
def registry(_=Depends(admin)):
    reg = DATA / "registry"
    read = lambda n: (reg / n).read_text() if (reg / n).exists() else ""
    try:
        market = json.loads(read("marketplace.json") or "{}")
    except ValueError:
        market = {}
    return {"registry": publisher.load(), "managed_mcp": read("managed-mcp.json"), "signature": read("managed-mcp.json.sig"),
            "public_key": publisher.public_key_pem(), "marketplace": {**market, "url": publisher.marketplace_url(), "name": publisher.MARKET_NAME}}


class Revoke(BaseModel):
    reason: str


@app.post("/api/registry/{name}/revoke")
def revoke(name: str, body: Revoke, who=Depends(admin)):
    if not body.reason.strip():
        raise HTTPException(400, "사유를 적어 주세요")
    try:
        publisher.revoke(name, who, body.reason.strip())
    except KeyError:
        raise HTTPException(404)
    return {"ok": True}


@app.get("/admin/registry/{fname}")
def registry_file(fname: str, _=Depends(admin)):
    if fname not in ("managed-mcp.json", "managed-mcp.json.sig"):
        raise HTTPException(404)
    if fname == "managed-mcp.json" and not (DATA / "registry" / fname).exists():
        publisher.regenerate(publisher.load())
    return FileResponse(DATA / "registry" / fname, filename=fname)


@app.get("/approved/simple/")
def approved_index():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(publisher.simple_index())


@app.get("/approved/simple/{package}/")
def approved_package(package: str):
    """승인 안 된 패키지는 404 — 그래야 uv/pip 가 기본 인덱스(PyPI·사내 미러)로 넘어간다."""
    from fastapi.responses import HTMLResponse
    if not (publisher.APPROVED / publisher.norm(package)).is_dir():
        raise HTTPException(404)
    return HTMLResponse(publisher.simple_index(package))


@app.get("/approved/files/{package}/{fname}")
def approved_file(package: str, fname: str):
    p = publisher.APPROVED / publisher.norm(package) / fname
    if "/" in fname or not fname.endswith(".whl") or not p.exists():
        raise HTTPException(404)
    return FileResponse(p, filename=fname)


@app.get("/mcp")
def mcp_page(_=Depends(user)):
    return FileResponse(Path(__file__).parent / "static" / "mcp.html")


@app.get("/requests/{rid}")
def request_page(rid: str, _=Depends(user)):
    return FileResponse(Path(__file__).parent / "static" / "request.html")


@app.get("/admin/registry")
def registry_page(_=Depends(admin)):
    return FileResponse(Path(__file__).parent / "static" / "registry.html")


# ── 오탐 소명 · 활동 기록 · 신규 개발 · zip 올리기 · 모니터링 ─────────────────
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time as _time  # noqa: E402
import zipfile  # noqa: E402

from fastapi import File, Form, UploadFile  # noqa: E402

BLOCKING = {"critical", "high"}
EVENTS = DATA / "portal" / "events.jsonl"


def event(kind, who, **extra):
    with open(EVENTS, "a") as f:
        f.write(json.dumps({"ts": _time.time(), "kind": kind, "who": who, **extra}, ensure_ascii=False) + "\n")


def effective_verdict(res):
    """소명이 허용된 항목은 빼고 다시 센 판정. 원래 판정(res.verdict)은 그대로 둔다."""
    if res.get("verdict") == "오류":
        return "오류"
    live = [f for f in res.get("findings", []) if (f.get("appeal") or {}).get("status") != "accepted"]
    if any(f["severity"] in BLOCKING and f.get("level", "필수") == "필수" for f in live):   # 심화 감시자 항목은 막지 않음
        return "차단"
    return "검토" if live else "통과"


class Appeal(BaseModel):
    text: str


class AppealDecision(BaseModel):
    accept: bool
    note: str = ""


def _finding(req, fid):
    for f in (req.get("result") or {}).get("findings", []):
        if f["id"] == fid:
            return f
    raise HTTPException(404, "항목이 없습니다")


@app.post("/api/requests/{rid}/findings/{fid}/appeal")
def appeal(rid: str, fid: int, body: Appeal, u=Depends(user)):
    r = load_request(rid)
    if r["submitter"] != u["login"]:
        raise HTTPException(403, "요청한 개발자만 소명할 수 있습니다")
    if r["decision"] != "pending":
        raise HTTPException(409, "이미 결정된 요청입니다")
    if len(body.text.strip()) < 10:
        raise HTTPException(400, "왜 오탐인지 한두 문장으로 적어 주세요")
    f = _finding(r, fid)
    f["appeal"] = {"text": body.text.strip(), "by": u["login"], "at": _time.time(), "status": "pending"}
    save_request(r)
    event("appeal", u["login"], request=rid, finding=fid, title=f["title"])
    return f


@app.post("/api/requests/{rid}/findings/{fid}/appeal/decision")
def appeal_decision(rid: str, fid: int, body: AppealDecision, who=Depends(admin)):
    r = load_request(rid)
    if r["submitter"] == who:   # P5: 자기 소명을 자기가 허용하지 못한다
        raise HTTPException(403, "자기 소명은 다른 관리자가 판단해야 합니다")
    f = _finding(r, fid)
    if not f.get("appeal"):
        raise HTTPException(409, "소명이 없습니다")
    if not body.accept and not body.note.strip():
        raise HTTPException(400, "거절 사유를 적어 주세요")
    f["appeal"].update(status="accepted" if body.accept else "rejected", decided_by=who, decided_at=_time.time(), note=body.note.strip())
    r["result"]["effective_verdict"] = effective_verdict(r["result"])
    save_request(r)
    event("appeal_decision", who, request=rid, finding=fid, accept=body.accept)
    return {"finding": f, "effective_verdict": r["result"]["effective_verdict"]}


# 신규 개발: Gitea 에 내 저장소를 만들고 시작 코드를 넣는다
TEMPLATE_DEPS = "mcp==1.30.0\n"


def template_files(name, description):
    pkg = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") + "_mcp"
    entry = pkg.replace("_", "-")
    return {
        "kit-mcp.json": json.dumps({"name": name, "description": description, "entry": entry, "egress": []}, ensure_ascii=False, indent=2) + "\n",
        "requirements.txt": TEMPLATE_DEPS,
        ".gitignore": ".venv/\n__pycache__/\n*.egg-info/\nbuild/\ndist/\n",
        "pyproject.toml": f'''[project]
name = "{entry}"
version = "0.1.0"
requires-python = ">=3.10"
dynamic = ["dependencies"]

[project.scripts]
{entry} = "{pkg}.server:main"

[tool.setuptools.dynamic]
dependencies = {{ file = ["requirements.txt"] }}

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
''',
        f"{pkg}/__init__.py": "",
        f"{pkg}/server.py": f'''from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("{name}")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def hello(name: str) -> str:
    """Say hello. Replace this with your own tool."""
    return f"hello, {{name}}"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
''',
        "README.md": f"""# {name}

{description}

## 시험 (내 PC)

```
pip install -e .
mcp-test --with-extension "{entry}"
```

실행할 때마다 브라우저로 사내 로그인을 확인하고, 툴을 부를 때마다 승인을 묻습니다.
키(토큰)는 코드에 넣지 말고 kit-mcp.json 의 "secrets" 에 이름만 적은 뒤 사내 Git 비밀값에 넣습니다.

## 올리기

- `git push` 하거나 포털 MCP 등록 화면에서 zip 으로 올린 뒤 [검사 요청].
- 바깥 주소에 접속해야 하면 kit-mcp.json 의 `egress` 에 적어 주세요(관리자 승인).
- 의존성은 requirements.txt 에 `==` 로 고정합니다.
""",
    }


class NewProject(BaseModel):
    name: str
    description: str = ""


def gitea_admin_send(method, path, body=None, sudo=None):
    import base64
    auth = base64.b64encode(f"{os.environ.get('KIT_ADMIN_USER', 'kitadmin')}:{os.environ['PORTAL_ADMIN_PASSWORD']}".encode()).decode()
    headers = {"Authorization": "Basic " + auth, "Content-Type": "application/json"}
    if sudo:
        headers["Sudo"] = sudo
    req = urllib.request.Request(GITEA + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raise HTTPException(e.code if e.code < 500 else 502, f"Git: {e.read()[:300].decode(errors='replace')}")


@app.post("/api/projects")
def new_project(body: NewProject, u=Depends(user)):
    name = body.name.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,38}", name):
        raise HTTPException(400, "이름은 영문 소문자로 시작하고 소문자·숫자·- 만 (2~39자)")
    import base64
    gitea_admin_send("POST", f"/api/v1/admin/users/{urllib.parse.quote(u['login'])}/repos",
                     {"name": name, "private": True, "description": body.description, "default_branch": "main", "auto_init": False})
    files = [{"operation": "create", "path": p, "content": base64.b64encode(c.encode()).decode()}
             for p, c in template_files(name, body.description.strip() or name).items()]
    gitea_admin_send("POST", f"/api/v1/repos/{u['login']}/{name}/contents",
                     {"files": files, "message": "시작 코드 (MCP Dev Kit)", "branch": "main", "new_branch": "main"}, sudo=u["login"])
    event("project", u["login"], repo=f"{u['login']}/{name}")
    return {"repo": f"{u['login']}/{name}", "clone": f"{PUBLIC}/git/{u['login']}/{name}.git", "web": f"{PUBLIC}/git/{u['login']}/{name}"}


# zip 올리기: 내 저장소의 main 을 zip 내용으로 바꾸는 커밋 하나 → 바로 검사 요청
ZIP_MAX = 20 * 1024 * 1024


def safe_extract(zpath, dest):
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > 2000:
            raise HTTPException(400, "파일이 너무 많습니다 (2000개 넘음)")
        if sum(i.file_size for i in infos) > 100 * 1024 * 1024:
            raise HTTPException(400, "풀었을 때 100MB 를 넘습니다")
        for i in infos:
            p = Path(i.filename)
            if p.is_absolute() or ".." in p.parts or (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise HTTPException(400, f"허용하지 않는 경로: {i.filename}")
        z.extractall(dest)
    tops = [p for p in Path(dest).iterdir() if p.name not in ("__MACOSX",)]
    root = tops[0] if len(tops) == 1 and tops[0].is_dir() else Path(dest)   # 폴더째 압축한 경우
    for junk in (list(root.rglob("__pycache__")) + list(root.rglob(".git")) + list(root.glob(".venv")) + list(root.glob("venv"))
                 + list(root.rglob("*.egg-info")) + list(Path(dest).glob("__MACOSX"))):
        shutil.rmtree(junk, ignore_errors=True)
    return root


@app.post("/api/upload")
async def upload(repo: str = Form(...), message: str = Form("zip 으로 올림"), file: UploadFile = File(...), u=Depends(user)):
    if repo.split("/", 1)[0] != u["login"]:
        raise HTTPException(403, "내 저장소에만 올릴 수 있습니다")
    data = await file.read(ZIP_MAX + 1)
    if len(data) > ZIP_MAX:
        raise HTTPException(400, "zip 은 20MB 까지")
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "up.zip").write_bytes(data)
        try:
            src = safe_extract(d / "up.zip", d / "x")
        except zipfile.BadZipFile:
            raise HTTPException(400, "zip 파일이 아닙니다")
        if not (src / "kit-mcp.json").exists():
            raise HTTPException(400, "zip 최상위(또는 그 안 폴더 하나)에 kit-mcp.json 이 없습니다")
        pw = urllib.parse.quote(os.environ["PORTAL_ADMIN_PASSWORD"], safe="")
        url = f"http://{os.environ.get('KIT_ADMIN_USER', 'kitadmin')}:{pw}@127.0.0.1:3000/{repo}.git"
        wt = d / "wt"
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        run = lambda *a: subprocess.run(["git", *a], cwd=wt, capture_output=True, text=True, env=env, timeout=120)
        if subprocess.run(["git", "clone", "-q", url, str(wt)], capture_output=True, env=env, timeout=120).returncode != 0:
            raise HTTPException(400, f"{repo} 저장소를 열 수 없습니다")
        for p in wt.iterdir():
            if p.name != ".git":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
        shutil.copytree(src, wt, dirs_exist_ok=True)
        run("checkout", "-q", "-B", "main")
        run("add", "-A")
        if not run("status", "--porcelain").stdout.strip():
            changed = False
        else:
            run("-c", f"user.name={u['login']}", "-c", f"user.email={u['login']}@kit.local", "commit", "-q", "-m", message)
            p = run("push", "-q", "origin", "main")
            if p.returncode != 0:
                raise HTTPException(502, "올리지 못했습니다: " + p.stderr[-300:].replace(pw, "***"))
            changed = True
    event("upload", u["login"], repo=repo, bytes=len(data), changed=changed)
    req = new_request(NewRequest(repo=repo, ref="main"), u)
    return {"changed": changed, "request": req}


@app.get("/new")
def new_page(_=Depends(user)):
    return FileResponse(Path(__file__).parent / "static" / "new.html")


# 모니터링 (LiteLLM 밖 — 이 서버 전체)
def _tail_jsonl(path, limit=5000):
    try:
        lines = Path(path).read_text().splitlines()[-limit:]
    except FileNotFoundError:
        return []
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


@app.get("/api/monitor")
def monitor(hours: int = 24, _=Depends(admin)):
    since = _time.time() - hours * 3600
    llm = [e for e in _tail_jsonl("/data/logs/llm-access.jsonl", 20000) if e.get("ts", 0) >= since]
    per_user = {}
    for e in llm:
        p = per_user.setdefault(e.get("user") or "(키 틀림)", {"calls": 0, "denied": 0, "bytes_in": 0, "bytes_out": 0, "last": 0})
        p["calls"] += 1
        p["denied"] += e.get("status") in (401, 403)
        p["bytes_in"] += e.get("req_bytes", 0)
        p["bytes_out"] += e.get("resp_bytes", 0)
        p["last"] = max(p["last"], e["ts"])
    events = [e for e in _tail_jsonl(EVENTS) if e.get("ts", 0) >= since]
    try:
        status = {**egress.request("services"), **{k: v for k, v in egress.request("status").items() if k != "ok"}}
    except OSError as e:
        status = {"ok": False, "error": str(e)}
    eg = [x for x in egress_log(limit=5000, _="") if x["ts"] >= since]
    reqs = [json.loads(f.read_text()) for f in REQUESTS.glob("*.json")] if REQUESTS.exists() else []
    reqs = [r for r in reqs if r.get("created", 0) >= since]
    mem = dict(l.split(":", 1) for l in Path("/proc/meminfo").read_text().splitlines() if ":" in l)
    du = shutil.disk_usage("/data")
    return {
        "hours": hours,
        "system": {"load": os.getloadavg(), "mem_total_kb": int(mem["MemTotal"].split()[0]), "mem_avail_kb": int(mem["MemAvailable"].split()[0]),
                   "disk_total": du.total, "disk_used": du.used},
        "services": status.get("services", []),
        "llm": {"calls": len(llm), "users": per_user, "recent": llm[-30:][::-1]},
        "egress": {"allowed": sum(x["allowed"] for x in eg), "denied": sum(not x["allowed"] for x in eg),
                   "top_denied": sorted({x["target"] for x in eg if not x["allowed"]})[:20], "direct_blocked": status.get("direct_blocked")},
        "gate": {"requests": len(reqs), "by_verdict": {v: sum((r.get("result") or {}).get("verdict") == v for r in reqs) for v in ("통과", "검토", "차단", "오류")},
                 "appeals": sum(1 for r in reqs for f in (r.get("result") or {}).get("findings", []) if f.get("appeal"))},
        "events": events[-50:][::-1],
    }


@app.get("/admin/monitor")
def monitor_page(_=Depends(admin)):
    return FileResponse(Path(__file__).parent / "static" / "monitor.html")



# ── 역할 (주관리자 / 관리자 / 개발자) · 접근제어 ─────────────────────────
class RoleRequest(BaseModel):
    reason: str


@app.post("/api/roles/request")
def role_request(body: RoleRequest, u=Depends(user)):
    if u["is_admin"]:
        raise HTTPException(409, "이미 관리자입니다")
    if len(body.reason.strip()) < 5:
        raise HTTPException(400, "신청 사유를 적어 주세요")
    r = load_roles()
    r["requests"][u["login"]] = {"at": _time.time(), "reason": body.reason.strip()}
    save_roles(r)
    event("role_request", u["login"])
    return {"ok": True}


@app.get("/api/roles")
def roles_list(_=Depends(superadmin)):
    users = json.loads(gitea_admin("/api/v1/admin/users?limit=200"))
    r = load_roles()
    return {"users": [{"login": x["login"], "email": x.get("email", ""), "created": x.get("created"),
                       "role": role_of(x["login"], x.get("is_admin")), "request": r["requests"].get(x["login"]),
                       "granted": r["admins"].get(x["login"])} for x in users]}


class RoleSet(BaseModel):
    login: str
    role: str   # admin | dev


@app.post("/api/roles")
def roles_set(body: RoleSet, who=Depends(superadmin)):
    if body.role not in ("admin", "dev"):
        raise HTTPException(400)
    r = load_roles()
    if body.role == "admin":
        r["admins"][body.login] = {"by": who, "at": _time.time()}
    else:
        r["admins"].pop(body.login, None)
    r["requests"].pop(body.login, None)
    save_roles(r)
    event("role_set", who, login=body.login, role=body.role)
    return {"ok": True}


class AccessRule(BaseModel):
    cidr: str
    memo: str = ""


class AccessConf(BaseModel):
    mode: str            # all | list
    entries: list[AccessRule] = []
    confirm: bool = False


ACCESS = DATA / "portal" / "access.json"


@app.get("/api/access")
def access_get(u=Depends(user), _=Depends(superadmin)):
    try:
        a = json.loads(ACCESS.read_text())
    except FileNotFoundError:
        a = {"mode": "all", "entries": []}
    return {**a, "my_ip": u["ip"]}


@app.put("/api/access")
def access_put(body: AccessConf, u=Depends(user), who=Depends(superadmin)):
    import ipaddress
    if body.mode not in ("all", "list"):
        raise HTTPException(400)
    nets = []
    for e in body.entries:
        try:
            nets.append(ipaddress.ip_network(e.cidr.strip(), strict=False))
        except ValueError:
            raise HTTPException(400, f"IP·CIDR 형식이 아님: {e.cidr}")
    if body.mode == "list" and not body.confirm:
        try:
            mine = ipaddress.ip_address(u["ip"])
        except ValueError:
            mine = None
        if not mine or not any(mine in n for n in nets):
            raise HTTPException(400, f"지금 접속한 IP({u['ip']})가 목록에 없어 저장하면 잠깁니다")
    a = {"mode": body.mode, "entries": [{"cidr": str(n), "memo": e.memo.strip()} for n, e in zip(nets, body.entries)],
         "by": who, "at": _time.time()}
    ACCESS.write_text(json.dumps(a, ensure_ascii=False, indent=1))
    reply = egress.request("access")
    if not reply.get("ok"):
        raise HTTPException(500, reply.get("error", "적용 실패"))
    event("access", who, mode=body.mode, entries=len(nets))
    return a


@app.get("/admin/users")
def users_page(_=Depends(superadmin)):
    return FileResponse(Path(__file__).parent / "static" / "users.html")


# ── 개발자 PC 정책 (mcp-test 가 실행할 때마다 받아 srt 샌드박스로 적용) ─────────
DEVPOLICY = DATA / "portal" / "devpolicy.json"
DEVPOLICY_DEFAULT = {"version": 1, "sandbox": "required", "allowed_domains": [],
                     "goose_mode": {"session": "approve", "run": "auto"}, "workspace_only": True,
                     "linux_container_mode": False,   # True = 도커·WSL 같은 컨테이너 개발환경용 srt 약한 모드 (유닉스 소켓 차단 빠짐)
                     # P4: 사람 승인 강제 — 대화형은 늘 매번 묻기, 물을 화면이 없는 run 은 툴 호출 없는 chat 만. 개발자가 끌 수 없다.
                     "hitl_required": True,
                     # P21: MCP 비밀값을 어디서 꺼내 줄지 — kms(키 중앙관리·상) · keyring(PC 의 OS 암호화 저장소·상) · env(PC 환경 변수·하)
                     "secret_sources": ["kms", "keyring", "env"]}
SECRET_SOURCES = ("kms", "keyring", "env")
DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:\d{1,5})?$")


def load_devpolicy():
    try:
        return {**DEVPOLICY_DEFAULT, **json.loads(DEVPOLICY.read_text())}
    except FileNotFoundError:
        return dict(DEVPOLICY_DEFAULT)


def devpolicy_for_client():
    p = load_devpolicy()
    u = urllib.parse.urlparse(PUBLIC)
    host = u.hostname if u.port in (None, 443) else f"{u.hostname}:{u.port}"   # srt: IP 는 포트까지 적어야 허용
    return {**p, "kit_host": host, "network_allowed": sorted({host, *p["allowed_domains"]})}


@app.get("/api/devkit/policy")
def devkit_policy(request: Request):
    """mcp-test 가 실행할 때마다 실행 토큰으로 받는다. 받은 기록이 모니터링에 남는다."""
    login = token_user(request)
    if not login:
        raise HTTPException(401, "실행 토큰이 없거나 지났습니다")
    event("policy_fetch", login, ua=request.headers.get("user-agent", "")[:80],
          mode=request.query_params.get("mode", ""), ip=request.headers.get("x-real-ip", ""))
    return devpolicy_for_client()


class RunReport(BaseModel):
    event: str            # start | end
    mode: str = ""
    os: str = ""
    code: int | None = None
    secrets: list[str] = []


@app.post("/api/devkit/run")
def devkit_run(body: RunReport, request: Request):
    """개발 PC 실행 기록(P12) — mcp-test 가 시작·끝에 남긴다(비밀값은 이름만)."""
    login = token_user(request)
    if not login:
        raise HTTPException(401)
    event("devpc_" + ("end" if body.event == "end" else "start"), login, mode=body.mode, os=body.os, code=body.code,
          secrets=body.secrets[:30], ip=request.headers.get("x-real-ip", ""))
    return {"ok": True}


class SecretAsk(BaseModel):
    names: list[str]
    repo: str = ""


@app.post("/api/devkit/secrets")
def devkit_secrets(body: SecretAsk, request: Request):
    """mcp-test 가 실행 토큰으로 묻는다 — 그 사람 자신의 비밀값만(P15·P21). 값은 응답으로만 가고 어디에도 남기지 않는다."""
    login = token_user(request)
    if not login:
        raise HTTPException(401, "실행 토큰이 없거나 지났습니다")
    if "kms" not in load_devpolicy()["secret_sources"]:
        raise HTTPException(403, "관리자가 키 중앙관리 출처를 끄셨습니다")
    names = [n for n in body.names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n)][:30]
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "kit-secrets"))
    import agent as secrets_agent
    r = secrets_agent.request({"cmd": "user", "login": login, "names": names, "repo": body.repo})
    if not r.get("ok"):
        raise HTTPException(502, "키 저장소 오류: " + r.get("error", ""))
    event("secrets", login, names=sorted(r["values"]), missing=r["missing"], ip=request.headers.get("x-real-ip", ""))   # 이름만 기록
    return {"values": r["values"], "missing": r["missing"]}


@app.get("/api/secrets/names")
def my_secret_names(u=Depends(user)):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "kit-secrets"))
    import agent as secrets_agent
    r = secrets_agent.request({"cmd": "names", "login": u["login"]})
    return {"names": r.get("names", []), "manage": f"{PUBLIC}/git/user/settings/actions/secrets"}


class DevPolicy(BaseModel):
    sandbox: str                  # required | off
    allowed_domains: list[str] = []
    goose_mode_session: str = "approve"
    goose_mode_run: str = "auto"
    linux_container_mode: bool = False
    hitl_required: bool = True
    secret_sources: list[str] = ["kms", "keyring", "env"]
    expected_version: int


@app.get("/api/devpolicy")
def devpolicy_get(_=Depends(admin)):
    return devpolicy_for_client()


@app.put("/api/devpolicy")
def devpolicy_put(body: DevPolicy, who=Depends(superadmin)):
    cur = load_devpolicy()
    if body.expected_version != cur["version"]:
        raise HTTPException(409, "그 사이 다른 관리자가 바꿨습니다. 새로 고쳐 주세요")
    modes = {"approve", "smart_approve", "auto", "chat"}
    if body.sandbox not in ("required", "off") or body.goose_mode_session not in modes or body.goose_mode_run not in modes:
        raise HTTPException(400, "값이 올바르지 않습니다")
    if not body.secret_sources or any(x not in SECRET_SOURCES for x in body.secret_sources):
        raise HTTPException(400, "비밀값 출처는 kms · keyring · env 중에서 하나 이상")
    if body.hitl_required and body.goose_mode_session != "approve":
        raise HTTPException(400, "사람 승인 강제를 켜면 대화형 툴 호출은 '매번 묻기' 여야 합니다")
    doms = []
    for d in body.allowed_domains:
        d = d.strip().lower()
        if not DOMAIN_RE.match(d):
            raise HTTPException(400, f"도메인 형식이 아님: {d}")
        doms.append(d)
    new = {"version": cur["version"] + 1, "sandbox": body.sandbox, "allowed_domains": sorted(set(doms)),
           "goose_mode": {"session": body.goose_mode_session, "run": body.goose_mode_run}, "workspace_only": True,
           "linux_container_mode": body.linux_container_mode, "hitl_required": body.hitl_required,
           "secret_sources": [x for x in SECRET_SOURCES if x in body.secret_sources], "by": who, "at": _time.time()}
    DEVPOLICY.write_text(json.dumps(new, ensure_ascii=False, indent=1))
    event("devpolicy", who, version=new["version"], sandbox=new["sandbox"], domains=len(doms))
    return devpolicy_for_client()


@app.get("/admin/devpolicy")
def devpolicy_page(_=Depends(admin)):
    return FileResponse(Path(__file__).parent / "static" / "devpolicy.html")


# ── 거버넌스 화면: 감시자(P17) · 자산 현황(P18·P19) · 정규식 차단(P20) ────────
import governance  # noqa: E402
from types import SimpleNamespace  # noqa: E402

_h = SimpleNamespace(user=user, admin=admin, superadmin=superadmin, event=event, gitea_admin=gitea_admin,
                     publisher=publisher, REQUESTS=REQUESTS, effective_verdict=effective_verdict)
governance.register(app, _h)

# ── 버전 관리: 배포 묶음 목록·설치·진행 상태 · 적용 중 잠금 ─────────────────
import versions  # noqa: E402

versions.register(app, _h)
