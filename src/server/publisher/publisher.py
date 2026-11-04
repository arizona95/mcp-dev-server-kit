"""게시기 — 승인·되돌리기 → 레지스트리 · 승인 패키지 저장소 · managed-mcp.json(+서명).

managed-mcp.json 형식: https://code.claude.com/docs/en/managed-mcp (project .mcp.json 과 같은 mcpServers 맵).
임직원 PC 는 uvx 로 승인 패키지 저장소(KIT_PUBLIC_URL/approved/simple)에서 검사한 그 휠을 받아 실행한다.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import urllib.error
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA = Path(os.environ.get("KIT_DATA", "/data"))
REG = DATA / "registry"
REGISTRY = REG / "registry.json"
APPROVED = REG / "approved"
HISTORY = REG / "history.jsonl"
KEY = DATA / "publisher" / "signing_key.pem"
RESOURCES = REG / "resources"   # 배포 자원(.mcpb·.zip) — resources.py


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def load():
    try:
        return json.loads(REGISTRY.read_text())
    except FileNotFoundError:
        return {}


def _write(path, text):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def signing_key():
    if not KEY.exists():
        KEY.parent.mkdir(parents=True, exist_ok=True)
        KEY.write_bytes(Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        KEY.chmod(0o600)
    return serialization.load_pem_private_key(KEY.read_bytes(), password=None)


def public_key_pem():
    return signing_key().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def managed_mcp(registry):
    public = os.environ["KIT_PUBLIC_URL"].rstrip("/")
    servers = {}
    for name, e in sorted(registry.items()):
        if e["status"] != "approved":
            continue
        servers[name] = {"type": "stdio", "command": "uvx",
                         # rug pull 방지(P16): 의존성까지 검사 때 받은 그 휠만 — PyPI 를 보지 않으니 승인 뒤 새 버전이 끼어들 수 없다
                         "args": ["--default-index", f"{public}/approved/simple",
                                  "--from", f"{e['package']}=={e['version']}", e["entry"]],
                         # uv 는 기본으로 내장 루트 인증서만 본다 → 사내 CA(OS 저장소)를 쓰게
                         "env": {"UV_NATIVE_TLS": "true", "UV_SYSTEM_CERTS": "true"}}
    return {"mcpServers": servers}


def regenerate(registry):
    REG.mkdir(parents=True, exist_ok=True)
    text = json.dumps(managed_mcp(registry), indent=2, ensure_ascii=False) + "\n"
    _write(REG / "managed-mcp.json", text)
    _write(REG / "managed-mcp.json.sig", base64.b64encode(signing_key().sign(text.encode())).decode() + "\n")
    try:
        result = sync_marketplace(registry)
    except Exception as e:   # 마켓플레이스가 안 돼도 managed-mcp.json 배포는 그대로
        result = {"changed": False, "error": f"{type(e).__name__}: {e}"}
    _write(REG / "marketplace.json", json.dumps({**result, "at": time.time()}, ensure_ascii=False))


def rebuild_resources(registry):
    """승인 상태인 MCP 마다 배포 자원을 다시 만든다(이 기능 전에 승인한 것·형식을 바꾼 뒤)."""
    import resources
    servers = managed_mcp(registry)["mcpServers"]
    for name, e in registry.items():
        if e["status"] == "approved":
            try:
                e["resources"] = resources.build_all(name, e, servers[name], RESOURCES, APPROVED, norm)
                e.pop("resources_error", None)
            except Exception as ex:
                e["resources_error"] = f"{type(ex).__name__}: {ex}"
    _write(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=1))
    regenerate(registry)


def _history(action, name, who, **extra):
    with open(HISTORY, "a") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, "name": name, "who": who, **extra}, ensure_ascii=False) + "\n")


def approve(req, who, identity=None):
    res = req["result"]
    art = DATA / "gate" / "artifacts" / req["id"]
    wheel = art / res["wheel"]
    package, version = res["wheel"].split("-")[0], res["wheel"].split("-")[1]
    owner = req["repo"].split("/", 1)[0]
    registry = load()
    for other, e in registry.items():   # 개발자 사이 침해 방지(P15): 남의 패키지 이름으로 휠을 올리지 못한다
        if e.get("package") == norm(package) and other != req["name"] and e["repo"].split("/", 1)[0] != owner:
            raise ValueError(f"패키지 이름 {norm(package)} 은 {e['repo']} 의 것입니다. pyproject 의 name 을 바꿔 주세요.")
    # 검사 때 받은 휠 전부(이 MCP + 의존성 — 리눅스·윈도우) — 같은 파일 이름이 다른 내용이면 거부
    wheels = sorted(art.glob("*.whl"))
    lock = []
    for w in wheels:
        dest = APPROVED / norm(w.name.split("-")[0])
        digest = hashlib.sha256(w.read_bytes()).hexdigest()
        target = dest / w.name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError(f"{w.name} 은 이미 다른 내용으로 승인돼 있습니다. 버전을 올려 다시 요청해 주세요.")
        lock.append({"file": w.name, "sha256": digest})
    for w in wheels:
        dest = APPROVED / norm(w.name.split("-")[0])
        dest.mkdir(parents=True, exist_ok=True)
        if not (dest / w.name).exists():
            shutil.copy(w, dest / w.name)
    digest = next(x["sha256"] for x in lock if x["file"] == res["wheel"])
    registry[req["name"]] = {"status": "approved", "package": norm(package), "version": version, "entry": res["manifest"]["entry"],
                             "repo": req["repo"], "commit": res["commit"], "wheel": res["wheel"], "sha256": digest,
                             "tools": [{"name": t["name"], "description": t.get("description", "")} for t in res.get("tools", [])],
                             "egress": res["manifest"].get("egress", []), "request_id": req["id"],
                             "publisher": identity or {"login": owner}, "lock": lock, "deps_lock": res.get("deps_lock", []),
                             "approved_by": who, "approved_at": time.time()}
    try:
        import resources
        registry[req["name"]]["resources"] = resources.build_all(req["name"], registry[req["name"]], managed_mcp(registry)["mcpServers"][req["name"]],
                                                                 RESOURCES, APPROVED, norm)
    except Exception as e:   # 자원을 못 만들어도 승인·managed-mcp.json 배포는 그대로
        registry[req["name"]]["resources_error"] = f"{type(e).__name__}: {e}"
    _write(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=1))
    regenerate(registry)
    _history("approve", req["name"], who, request_id=req["id"], version=version)
    return registry[req["name"]]


def revoke(name, who, reason):
    registry = load()
    if name not in registry:
        raise KeyError(name)
    registry[name].update(status="revoked", revoked_by=who, revoked_at=time.time(), revoke_reason=reason)
    registry[name].pop("resources", None)
    shutil.rmtree(RESOURCES / name, ignore_errors=True)   # 되돌린 MCP 의 배포 자원은 더 내주지 않는다(P11)
    _write(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=1))
    regenerate(registry)
    _history("revoke", name, who, reason=reason)


def served_files():
    """승인 저장소가 지금 내주는 휠 = 지금 '승인' 상태인 MCP 마다 검사 때 고정한 휠(lock)만 — 되돌린 MCP·옛 버전은 내주지 않는다
    (MDM 으로 새 managed-mcp.json 을 아직 못 받은 PC 나 손으로 uvx 를 돌려도 되돌린 MCP 를 받지 못하게, P11)."""
    files = set()
    for e in load().values():
        if e.get("status") == "approved":
            files.update(x["file"] for x in e.get("lock") or [{"file": e["wheel"]}])
    return files


def simple_index(package=None):
    """PEP 503 간단 인덱스 — 지금 승인된 MCP 의 휠만(served_files)."""
    served = served_files()
    if package is None:
        names = sorted(p.name for p in APPROVED.iterdir() if p.is_dir() and any(f.name in served for f in p.glob("*.whl"))) \
            if APPROVED.exists() else []
        return "<!doctype html><html><body>\n" + "\n".join(f'<a href="{n}/">{n}</a>' for n in names) + "\n</body></html>\n"
    d = APPROVED / norm(package)
    files = sorted(f for f in d.glob("*.whl") if f.name in served) if d.exists() else []
    return "<!doctype html><html><body>\n" + "\n".join(
        f'<a href="/approved/files/{d.name}/{f.name}#sha256={hashlib.sha256(f.read_bytes()).hexdigest()}">{f.name}</a>' for f in files) + "\n</body></html>\n"


# ── Claude Code 플러그인 마켓플레이스 (사내 Git 저장소) ─────────────────────
# 형식: https://code.claude.com/docs/en/plugin-marketplaces · host-marketplace
# 승인 MCP 하나 = 플러그인 하나(.mcp.json 에 managed-mcp.json 과 같은 uvx 명령). 되돌린 것은 renames: null +
# forceRemoveDeletedPlugins 로 임직원 PC 에서도 지워진다. 임직원은 marketplace add 한 번 → marketplace update(또는 자동 업데이트).
MARKET_OWNER = os.environ.get("KIT_ADMIN_USER", "kitadmin")
MARKET_REPO = "mcp-marketplace"
MARKET_NAME = os.environ.get("KIT_MARKETPLACE_NAME", "sds-mcp")
# 임직원 사용자 PC 가 받는 주소 = 포털이 내주는 읽기 전용 사본(git dumb HTTP). 사내 Git 은 로그인해야 보이므로(REQUIRE_SIGNIN_VIEW)
# Gitea 계정이 없는 사용자도 받을 수 있게 한다. 들어 있는 것은 플러그인 설정뿐(승인 저장소 /approved/simple 처럼 공개 읽기).
MARKET_MIRROR = REG / "marketplace.git"


def marketplace_url():
    return f"{os.environ['KIT_PUBLIC_URL'].rstrip('/')}/market/{MARKET_NAME}.git"


def gitea_marketplace_url():
    return f"{os.environ['KIT_PUBLIC_URL'].rstrip('/')}/git/{MARKET_OWNER}/{MARKET_REPO}.git"


def _mirror(run):
    """작업 사본의 main 을 읽기 전용 사본으로 — 바뀐 것이 없어도(사본이 처음이거나 지워졌을 때) 맞춘다."""
    import subprocess
    if not (MARKET_MIRROR / "HEAD").exists():
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(MARKET_MIRROR)], capture_output=True, timeout=30)
    run("push", "-q", "-f", str(MARKET_MIRROR), "main:main")
    subprocess.run(["git", "-C", str(MARKET_MIRROR), "update-server-info"], capture_output=True, timeout=30)


def marketplace_files(registry):
    servers = managed_mcp(registry)["mcpServers"]
    plugins, files, renames = [], {}, {}
    for name, e in sorted(registry.items()):
        if e["status"] != "approved":
            renames[name] = None
            continue
        desc = "; ".join(t["name"] for t in e.get("tools", []))
        plugins.append({"name": name, "source": f"./plugins/{name}", "description": f"사내 승인 MCP — 툴: {desc}"})
        pub = e.get("publisher") or {}
        files[f"plugins/{name}/.claude-plugin/plugin.json"] = {"name": name, "version": e["version"],
                                                                "description": f"사내 승인 MCP ({e['repo']}@{e['commit'][:10]})",
                                                                "author": {k: v for k, v in (("name", pub.get("name") or pub.get("login", "")),
                                                                                             ("email", pub.get("email", ""))) if v}}
        files[f"plugins/{name}/.mcp.json"] = {"mcpServers": {name: servers[name]}}
    market = {"name": MARKET_NAME, "description": "MCP Dev Kit 에서 검사·승인된 MCP", "owner": {"name": "MCP Dev Kit"},
              "plugins": plugins, "forceRemoveDeletedPlugins": True}
    if renames:
        market["renames"] = renames
    files[".claude-plugin/marketplace.json"] = market
    files["README.md"] = (f"# {MARKET_NAME}\n\n사내 MCP Dev Kit 이 승인·되돌리기 때마다 자동으로 고치는 저장소입니다. 손으로 고치지 마세요.\n\n"
                          f"```\nclaude plugin marketplace add {marketplace_url()}\nclaude plugin install <이름>@{MARKET_NAME}\n"
                          f"claude plugin marketplace update {MARKET_NAME}\n```\n")
    return files


def sync_marketplace(registry, who="kit"):
    """마켓플레이스 저장소를 레지스트리와 같게 만든다. 바뀐 것이 있을 때만 커밋. 실패해도 승인 자체는 막지 않고 까닭을 돌려준다."""
    import subprocess
    import tempfile
    import urllib.parse
    import urllib.request
    pw = os.environ["PORTAL_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"{MARKET_OWNER}:{pw}".encode()).decode()
    api = "http://127.0.0.1:3000/api/v1"
    try:
        urllib.request.urlopen(urllib.request.Request(f"{api}/repos/{MARKET_OWNER}/{MARKET_REPO}", headers={"Authorization": "Basic " + auth}), timeout=10)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        body = json.dumps({"name": MARKET_REPO, "private": False, "default_branch": "main",
                           "description": "검사·승인된 MCP 의 Claude Code 플러그인 마켓플레이스 (자동)"}).encode()
        urllib.request.urlopen(urllib.request.Request(f"{api}/user/repos", data=body, method="POST",
                                                      headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"}), timeout=10)
    url = f"http://{MARKET_OWNER}:{urllib.parse.quote(pw, safe='')}@127.0.0.1:3000/{MARKET_OWNER}/{MARKET_REPO}.git"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    with tempfile.TemporaryDirectory() as d:
        wt = Path(d) / "m"
        run = lambda *a: subprocess.run(["git", *a], cwd=wt, capture_output=True, text=True, env=env, timeout=60)
        if subprocess.run(["git", "clone", "-q", url, str(wt)], capture_output=True, env=env, timeout=60).returncode != 0:
            wt.mkdir()
            run("init", "-q", "-b", "main")
            run("remote", "add", "origin", url)
        for p in wt.iterdir():
            if p.name != ".git":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
        for rel, content in marketplace_files(registry).items():
            f = wt / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, indent=2) + "\n")
        run("checkout", "-q", "-B", "main")
        run("add", "-A")
        if not run("status", "--porcelain").stdout.strip():
            _mirror(run)
            return {"changed": False, "url": marketplace_url()}
        run("-c", "user.name=MCP Dev Kit", "-c", "user.email=kit@kit.local", "commit", "-q", "-m", f"레지스트리 반영 ({who})")
        p = run("push", "-q", "origin", "main")
        if p.returncode != 0:
            return {"changed": False, "error": p.stderr[-300:].replace(pw, "***"), "url": marketplace_url()}
        _mirror(run)
        return {"changed": True, "commit": run("rev-parse", "--short", "HEAD").stdout.strip(), "url": marketplace_url()}
