"""업데이트 에이전트 (root) — 배포 묶음 목록·서명 확인 · [설치] 를 받으면 새 이미지를 불러와 '업데이트 담당' 컨테이너를 띄운다.

배포 묶음(한 버전 = 폴더 하나): mcp-dev-server-kit-v<버전>/
  mcp-dev-server-kit-v<버전>.tar   키트 이미지(검사용 격리 이미지 포함)
  manifest.json                    버전·구성요소 버전표(kit version --json) · 이미지 tar 의 sha256
  manifest.json.sig                manifest.json 의 Ed25519 서명 — 이 이미지에 든 공개 키(release.pub)로 확인
  SHA256SUMS · install.sh          (처음 설치용)
찾는 곳: /releases (호스트 /srv/kit/releases 를 읽기 전용으로 붙임) · /data/releases (포털에서 올린 것).
인터넷에서 받지 않는다 — 관리자가 넣은 묶음만, 서명이 맞을 때만 설치한다.
요청(유닉스 소켓 /run/kit-update.sock, 포털 kit 그룹만): {"cmd":"list"} · {"cmd":"install","version":"1.0.1","who":"…"}
"""
import base64
import grp
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

SOCK = "/run/kit-update.sock"
ROOTS = [Path("/releases"), Path("/data/releases")]
PUB = Path("/opt/kit/server/release.pub")
STATUS = Path("/data/update/status.json")
_hash_cache = {}


def sha256(path):
    st = path.stat()
    key = (str(path), st.st_mtime, st.st_size)
    if key not in _hash_cache:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _hash_cache[key] = h.hexdigest()
    return _hash_cache[key]


def current():
    out = subprocess.run(["/opt/kit/venv/bin/python", "/opt/kit/server/kit-cli/version.py", "--json"], capture_output=True, text=True).stdout
    return json.loads(out)


def check(folder):
    """묶음 하나를 확인한다 — 서명 · 이미지 해시 · 구성요소. 문제가 있으면 problems 에 까닭."""
    r = {"path": str(folder), "problems": []}
    mf, sig = folder / "manifest.json", folder / "manifest.json.sig"
    try:
        raw = mf.read_bytes()
        m = json.loads(raw)
    except Exception as e:
        return {**r, "problems": [f"manifest.json 을 읽지 못함: {e}"]}
    r.update(version=m.get("version"), built=m.get("built"), components=m.get("components", []), image=m.get("image"))
    try:
        serialization.load_pem_public_key(PUB.read_bytes()).verify(base64.b64decode(sig.read_text().strip()), raw)
        r["signed"] = True
    except Exception:
        r["signed"] = False
        r["problems"].append("서명이 맞지 않거나 없음 — 회사가 만든 묶음이 아닐 수 있어 설치할 수 없습니다")
    tar = folder / (m.get("image") or "")
    if not m.get("image") or not tar.exists():
        r["problems"].append("이미지 tar 가 없음")
    elif sha256(tar) != m.get("image_sha256"):
        r["problems"].append("이미지 tar 의 해시가 manifest 와 다름 — 파일이 바뀌었거나 덜 복사됨")
    return r


def listing():
    cur = current()
    have = {c["name"]: c["version"] for c in cur["components"]}
    out = []
    for root in ROOTS:
        for mf in sorted(root.glob("*/manifest.json")) if root.exists() else []:
            r = check(mf.parent)
            r["changes"] = [{"name": c["name"], "from": have.get(c["name"], ""), "to": c["version"]}
                            for c in r.get("components", []) if have.get(c["name"]) != c["version"]]
            out.append(r)
    out.sort(key=lambda r: [int(x) if x.isdigit() else x for x in str(r.get("version", "")).split(".")], reverse=True)
    return {"current": cur, "releases": out}


def me():
    cid = Path("/etc/hostname").read_text().strip()
    info = json.loads(subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=True).stdout)[0]
    vol = next(m["Name"] for m in info["Mounts"] if m["Destination"] == "/data")
    return info["Name"].lstrip("/"), vol


def install(version, who):
    if STATUS.exists() and json.loads(STATUS.read_text()).get("state") in ("running", "rolling_back"):
        return {"ok": False, "error": "이미 업데이트가 진행 중입니다"}
    rel = next((r for r in listing()["releases"] if r.get("version") == version), None)
    if not rel:
        return {"ok": False, "error": f"v{version} 묶음이 없습니다"}
    if rel["problems"]:
        return {"ok": False, "error": " · ".join(rel["problems"])}
    cur = current()["version"]
    if version == cur:
        return {"ok": False, "error": f"이미 v{cur} 입니다"}
    threading.Thread(target=_apply, args=(rel, cur, version, who), daemon=True).start()   # 이미지 불러오기는 오래 걸린다 — 바로 돌려준다
    return {"ok": True}


def _apply(rel, cur, version, who):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps({"state": "running", "from": cur, "to": version, "started": time.time(), "who": who, "pct": 0,
                                  "steps": [{"name": "새 이미지 불러오기", "state": "running"}], "log": []}, ensure_ascii=False))
    os.chmod(STATUS, 0o644)
    folder = Path(rel["path"])
    p = subprocess.run(["docker", "load", "-i", str(folder / rel["image"])], capture_output=True, text=True, timeout=1800)
    if p.returncode != 0:
        STATUS.write_text(json.dumps({"state": "failed", "from": cur, "to": version, "message": "이미지를 불러오지 못했습니다: " + p.stderr[-300:]}, ensure_ascii=False))
        return
    image = f"mcp-dev-server-kit:{version}"
    name, vol = me()
    for c in subprocess.run(["docker", "ps", "-a", "--filter", "name=kit-updater-", "--filter", "status=exited", "--format", "{{.Names}}"],
                            capture_output=True, text=True).stdout.split():
        subprocess.run(["docker", "rm", c], capture_output=True)   # 지난 업데이트 담당(끝난 것) 정리
    upd = f"kit-updater-{int(time.time())}"
    r = subprocess.run(["docker", "run", "-d", "--name", upd, "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{vol}:/data",
                    "-e", f"KIT_OLD={name}", "-e", f"KIT_NEW_IMAGE={image}", "-e", f"KIT_VOLUME={vol}", "-e", f"KIT_FROM={cur}", "-e", f"KIT_TO={version}",
                    "--entrypoint", "/opt/kit/venv/bin/python", image, "/opt/kit/server/kit-cli/updater.py"], capture_output=True, text=True)
    if r.returncode != 0:
        STATUS.write_text(json.dumps({"state": "failed", "from": cur, "to": version, "message": "업데이트 담당을 띄우지 못했습니다: " + r.stderr[-300:]}, ensure_ascii=False))
        return
    with open("/data/portal/events.jsonl", "a") as f:
        f.write(json.dumps({"ts": time.time(), "kind": "update_start", "who": who, "from": cur, "to": version, "updater": upd}, ensure_ascii=False) + "\n")
    return upd


def handle(conn):
    try:
        req = json.loads(conn.recv(65536).decode())
        if req.get("cmd") == "list":
            out = {"ok": True, **listing()}
        elif req.get("cmd") == "install":
            out = install(str(req["version"]), req.get("who", ""))
        else:
            out = {"ok": False, "error": "모르는 명령"}
    except Exception as e:
        out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    conn.sendall(json.dumps(out, ensure_ascii=False).encode())
    conn.close()


def serve():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chown(SOCK, 0, grp.getgrnam("kit").gr_gid)
    os.chmod(SOCK, 0o660)
    s.listen(4)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def request(obj, timeout=1800):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(timeout)
    c.connect(SOCK)
    c.sendall(json.dumps(obj).encode())
    buf = b""
    while True:
        part = c.recv(65536)
        if not part:
            break
        buf += part
    return json.loads(buf)


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        serve()
