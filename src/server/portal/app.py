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
    return RedirectResponse("/login?next=" + urllib.parse.quote(request.url.path))


def user(request: Request):
    u = request.session.get("user")
    if not u:
        raise LoginRequired()
    return u


def admin(u=Depends(user)):
    if not u.get("is_admin"):
        raise HTTPException(403, "관리자만 볼 수 있습니다")
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
    request.session["user"] = {"login": me["login"], "is_admin": bool(me.get("is_admin"))}
    return RedirectResponse(request.session.pop("next", "/"))


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(f"{PUBLIC}/git/user/logout")


@app.get("/api/me")
def me(u=Depends(user)):
    return u


@app.get("/")
def home(u=Depends(user)):
    return RedirectResponse("/mcp")


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
def add_rule(rule: Rule, who=Depends(admin)):
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
def remove_rule(host: str, port: int, who=Depends(admin)):
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


def token_user(request: Request):
    """Authorization: Bearer <개인 키> → 로그인 이름. 없거나 틀리면 None."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    entry = load_tokens().get(token_hash(auth[7:].strip()))
    return entry["login"] if entry else None


@app.post("/api/token")
def issue_token(u=Depends(user)):
    """개인 키 새로 발급 — 예전 키는 바로 못 쓰게 된다. 값은 이번 응답에서만 보인다."""
    tokens = {h: e for h, e in load_tokens().items() if e["login"] != u["login"]}
    t = "kit-" + secrets.token_urlsafe(32)
    tokens[token_hash(t)] = {"login": u["login"], "created": __import__("time").time()}
    TOKENS.write_text(json.dumps(tokens))
    TOKENS.chmod(0o600)
    return {"token": t}


@app.get("/api/token")
def token_info(u=Depends(user)):
    mine = [e for e in load_tokens().values() if e["login"] == u["login"]]
    return {"has_token": bool(mine), "created": mine[0]["created"] if mine else None}


@app.get("/_auth/llm")
def auth_llm(request: Request):
    """nginx auth_request: /llm/ 요청마다 개인 키를 확인한다."""
    login = token_user(request)
    if not login:
        return JSONResponse({"detail": "개인 키가 없거나 틀렸습니다"}, status_code=401)
    return JSONResponse({"login": login}, headers={"X-Kit-User": login})


def render_installer(name, os_name):
    file, digest = goose_files()[os_name]
    ca = CA_FILE.read_text().strip() if CA_FILE.exists() else ""
    text = (DEVKIT / "installer" / name).read_text()
    for k, v in {"PUBLIC": PUBLIC, "GOOSE_FILE": file, "GOOSE_SHA256": digest, "CA_PEM": ca}.items():
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
    """goose 파일 — 로그인 세션이나 개인 키가 있어야 받는다."""
    if not (request.session.get("user") or token_user(request)):
        raise HTTPException(401, "로그인하거나 개인 키를 붙여 주세요")
    for os_name, (file, _) in goose_files().items():
        if name == file:
            return FileResponse(DEVKIT / "hosts" / "goose" / os_name / file, filename=file)
    raise HTTPException(404)


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
    rid = _t.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    REQUESTS.mkdir(parents=True, exist_ok=True)
    req = {"id": rid, "repo": body.repo, "ref": body.ref, "name": manifest.get("name", body.repo.split("/")[-1]),
           "submitter": u["login"], "created": _t.time(), "status": "queued", "decision": "pending"}
    save_request(req)
    return req


@app.get("/api/requests")
def list_requests(u=Depends(user)):
    out = []
    for f in sorted(REQUESTS.glob("*.json"), reverse=True) if REQUESTS.exists() else []:
        r = json.loads(f.read_text())
        if visible(r, u):
            res = r.get("result") or {}
            out.append({k: r.get(k) for k in ("id", "repo", "ref", "name", "submitter", "created", "status", "decision")} |
                       {"verdict": res.get("verdict"), "findings": len(res.get("findings", [])),
                        "flags": sorted({fl for t in (res.get("review") or {}).get("tools", []) for fl in t["flags"]})})
    return out


@app.get("/api/requests/{rid}")
def get_request(rid: str, u=Depends(user)):
    r = load_request(rid)
    if not visible(r, u):
        raise HTTPException(403)
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
    verdict = (r.get("result") or {}).get("verdict")
    if d.action == "approve":
        if verdict in ("차단", "오류"):
            raise HTTPException(409, f"검사 결과가 '{verdict}' 이라 승인할 수 없습니다")
        try:
            publisher.approve(r, who)
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
    return r


@app.get("/api/registry")
def registry(_=Depends(admin)):
    reg = DATA / "registry"
    read = lambda n: (reg / n).read_text() if (reg / n).exists() else ""
    return {"registry": publisher.load(), "managed_mcp": read("managed-mcp.json"), "signature": read("managed-mcp.json.sig"),
            "public_key": publisher.public_key_pem()}


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
