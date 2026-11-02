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
    default_index = os.environ.get("PYPI_INDEX_URL") or "https://pypi.org/simple"
    servers = {}
    for name, e in sorted(registry.items()):
        if e["status"] != "approved":
            continue
        servers[name] = {"type": "stdio", "command": "uvx",
                         "args": ["--index", f"{public}/approved/simple", "--default-index", default_index,
                                  "--from", f"{e['package']}=={e['version']}", e["entry"]],
                         # uv 는 기본으로 내장 루트 인증서만 본다 → 사내 CA(OS 저장소)를 쓰게
                         "env": {"UV_NATIVE_TLS": "true"}}
    return {"mcpServers": servers}


def regenerate(registry):
    REG.mkdir(parents=True, exist_ok=True)
    text = json.dumps(managed_mcp(registry), indent=2, ensure_ascii=False) + "\n"
    _write(REG / "managed-mcp.json", text)
    _write(REG / "managed-mcp.json.sig", base64.b64encode(signing_key().sign(text.encode())).decode() + "\n")


def _history(action, name, who, **extra):
    with open(HISTORY, "a") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, "name": name, "who": who, **extra}, ensure_ascii=False) + "\n")


def approve(req, who):
    res = req["result"]
    wheel = DATA / "gate" / "artifacts" / req["id"] / res["wheel"]
    package, version = res["wheel"].split("-")[0], res["wheel"].split("-")[1]
    dest = APPROVED / norm(package)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / res["wheel"]
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise ValueError(f"{res['wheel']} 은 이미 다른 내용으로 승인돼 있습니다. 버전을 올려 다시 요청해 주세요.")
    shutil.copy(wheel, target)
    registry = load()
    registry[req["name"]] = {"status": "approved", "package": norm(package), "version": version, "entry": res["manifest"]["entry"],
                             "repo": req["repo"], "commit": res["commit"], "wheel": res["wheel"], "sha256": digest,
                             "tools": [{"name": t["name"], "description": t.get("description", "")} for t in res.get("tools", [])],
                             "egress": res["manifest"].get("egress", []), "request_id": req["id"],
                             "approved_by": who, "approved_at": time.time()}
    _write(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=1))
    regenerate(registry)
    _history("approve", req["name"], who, request_id=req["id"], version=version)
    return registry[req["name"]]


def revoke(name, who, reason):
    registry = load()
    if name not in registry:
        raise KeyError(name)
    registry[name].update(status="revoked", revoked_by=who, revoked_at=time.time(), revoke_reason=reason)
    _write(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=1))
    regenerate(registry)
    _history("revoke", name, who, reason=reason)


def simple_index(package=None):
    """PEP 503 간단 인덱스 — 승인된 휠만."""
    if package is None:
        names = sorted(p.name for p in APPROVED.iterdir() if p.is_dir()) if APPROVED.exists() else []
        return "<!doctype html><html><body>\n" + "\n".join(f'<a href="{n}/">{n}</a>' for n in names) + "\n</body></html>\n"
    d = APPROVED / norm(package)
    files = sorted(d.glob("*.whl")) if d.exists() else []
    return "<!doctype html><html><body>\n" + "\n".join(
        f'<a href="/approved/files/{d.name}/{f.name}#sha256={hashlib.sha256(f.read_bytes()).hexdigest()}">{f.name}</a>' for f in files) + "\n</body></html>\n"
