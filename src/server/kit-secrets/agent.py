"""비밀값 에이전트 (root) — 키 중앙관리(P7·P21)의 '꺼내는 쪽'.

비밀값 저장소 = Gitea Actions 시크릿(GitHub Secrets 와 같은 기능 — 화면에서 넣기·지우기만 되고 다시 볼 수 없음).
Gitea 는 값을 hex(IV 16바이트 + AES-256-CFB(base64(값)))로, 열쇠 sha256(SECRET_KEY) 로 DB 에 저장한다(28.1.0 실측).
이 에이전트만 그 DB·열쇠를 읽고(root), 포털(kit 사용자)은 유닉스 소켓으로 '이 사람의 이 이름' 만 묻는다.
회사 KMS(Vault 호환)로 바꾸려면 fetch() 한 곳만 바꾼다 — 묻는 쪽(포털·LiteLLM 시작)은 그대로.

요청 한 줄 JSON:
  {"cmd": "user", "login": "kimdev", "names": ["GITHUB_TOKEN"], "repo": "kimdev/notes"(선택)} → 그 사람(과 그 사람 저장소)의 값
  {"cmd": "kit", "names": ["KIT_LLM_API_KEY"]} → 키트 관리자 계정(KIT_ADMIN_USER)의 값 — 서버 키
  {"cmd": "names", "login": "kimdev"} → 값 없이 이름만(화면 표시용)
"""
import base64
import binascii
import grp
import hashlib
import json
import os
import socket
import sqlite3
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SOCK = "/run/kit-secrets.sock"
GITEA_DB = os.environ.get("KIT_GITEA_DB", "/data/gitea/gitea.db")
SECRET_KEY = os.environ.get("KIT_GITEA_SECRET_KEY_FILE", "/data/gitea/secrets/secret_key")
KIT_ADMIN = os.environ.get("KIT_ADMIN_USER", "kitadmin")


def _key():
    with open(SECRET_KEY) as f:
        return hashlib.sha256(f.read().strip().encode()).digest()


def _decrypt(hexdata):
    raw = binascii.unhexlify(hexdata)
    d = Cipher(algorithms.AES(_key()), modes.CFB(raw[:16])).decryptor()
    return base64.b64decode(d.update(raw[16:]) + d.finalize()).decode()


def _db():
    return sqlite3.connect(f"file:{GITEA_DB}?mode=ro", uri=True, timeout=5)


def _uid(c, login):
    row = c.execute("select id from user where lower_name = ?", (login.lower(),)).fetchone()
    return row[0] if row else None


def fetch(login, names, repo=None):
    """그 사람의 사용자 시크릿 + (주면) 그 사람 소유 저장소의 시크릿. 저장소 쪽이 사용자 쪽보다 앞선다(더 좁은 범위)."""
    with _db() as c:
        uid = _uid(c, login)
        if uid is None:
            return {}, list(names)
        rows = {r[0]: r[1] for r in c.execute("select name, data from secret where owner_id = ? and repo_id = 0", (uid,))}
        if repo:
            owner, _, rname = repo.partition("/")
            if owner.lower() == login.lower():   # 남의 저장소 시크릿은 꺼내지 않는다(P15)
                rid = c.execute("select id from repository where owner_id = ? and lower_name = ?", (uid, rname.lower())).fetchone()
                if rid:
                    rows.update({r[0]: r[1] for r in c.execute("select name, data from secret where repo_id = ?", (rid[0],))})
    found, missing = {}, []
    for n in names:
        if n.upper() in rows:   # Gitea 는 시크릿 이름을 대문자로 저장한다
            found[n] = _decrypt(rows[n.upper()])
        else:
            missing.append(n)
    return found, missing


def names_of(login):
    with _db() as c:
        uid = _uid(c, login)
        return sorted(r[0] for r in c.execute("select name from secret where owner_id = ? and repo_id = 0", (uid,))) if uid else []


def handle(conn):
    try:
        req = json.loads(conn.recv(65536).decode())
        cmd = req.get("cmd")
        names = [n for n in req.get("names", []) if isinstance(n, str) and n.replace("_", "").isalnum()][:50]
        if cmd == "user":
            found, missing = fetch(req["login"], names, req.get("repo"))
            out = {"ok": True, "values": found, "missing": missing}
        elif cmd == "kit":
            found, missing = fetch(KIT_ADMIN, names)
            out = {"ok": True, "values": found, "missing": missing}
        elif cmd == "names":
            out = {"ok": True, "names": names_of(req["login"])}
        else:
            out = {"ok": False, "error": "모르는 명령"}
    except Exception as e:
        out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    conn.sendall(json.dumps(out).encode())
    conn.close()


def serve():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chown(SOCK, 0, grp.getgrnam("kit").gr_gid)   # 포털·LiteLLM(kit) 만 묻는다
    os.chmod(SOCK, 0o660)
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def request(obj, timeout=10):
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
    return json.loads(buf or b'{"ok": false, "error": "no reply"}')


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["serve"]:
        serve()
    elif sys.argv[1:2] == ["kit-env"]:   # LiteLLM 시작 때: 서버 키를 표준 출력으로(파일에 안 씀) — run.sh 가 받아 그 프로세스 환경에만
        r = request({"cmd": "kit", "names": sys.argv[2:]})
        for k, v in r.get("values", {}).items():
            print(f"{k}={v}")
