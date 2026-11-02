"""Gitea 가 뜬 뒤 한 번: 관리자 계정 · 반입 도구 저장소(kitadmin/mcp-remote) · 포털 로그인용 OAuth2 앱. 이미 있으면 건너뛴다."""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

DATA = Path(os.environ.get("KIT_DATA", "/data"))
GITEA = "http://127.0.0.1:3000"
ADMIN = os.environ.get("KIT_ADMIN_USER", "kitadmin")
OAUTH_FILE = DATA / "portal" / "oauth.json"


def call(method, path, body=None):
    auth = base64.b64encode(f"{ADMIN}:{os.environ['PORTAL_ADMIN_PASSWORD']}".encode()).decode()
    req = urllib.request.Request(GITEA + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")


TOOLS = Path("/opt/kit/devkit/hosts")


def publish_tool(name, desc):
    """이미지에 든 반입 도구(TOOLS/<name>)를 사내 Git kitadmin/<name> 에 올린다 — 버전 태그가 이미 있으면 건너뛴다.
    개발자 PC 는 인터넷 없이 여기서 받는다(로그인한 사람은 누구나 읽기)."""
    src = TOOLS / name
    lock = json.loads((src / "package-lock.json").read_text())
    version = lock["packages"][f"node_modules/{name}"]["version"]
    tag = f"v{version}"
    try:
        call("GET", f"/api/v1/repos/{ADMIN}/{name}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        call("POST", "/api/v1/user/repos", {"name": name, "description": desc, "private": False, "default_branch": "main"})
    try:
        call("GET", f"/api/v1/repos/{ADMIN}/{name}/tags/{tag}")
        return
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    auth = base64.b64encode(f"{ADMIN}:{os.environ['PORTAL_ADMIN_PASSWORD']}".encode()).decode()
    url = f"{GITEA}/{ADMIN}/{name}.git"
    git = ["git", "-c", f"http.extraHeader=Authorization: Basic {auth}", "-c", "user.name=" + ADMIN, "-c", f"user.email={ADMIN}@kit.local"]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / name
        subprocess.run(git + ["clone", "-q", url, str(work)], check=True, capture_output=True)
        for p in work.iterdir():
            if p.name != ".git":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
        shutil.copytree(src, work, dirs_exist_ok=True)
        subprocess.run(git + ["-C", str(work), "checkout", "-q", "-B", "main"], check=True)
        subprocess.run(git + ["-C", str(work), "add", "-A"], check=True)
        subprocess.run(git + ["-C", str(work), "commit", "-q", "-m", f"{name} {version} 반입 (출처·해시 SOURCE.md)"], check=True)
        subprocess.run(git + ["-C", str(work), "tag", tag], check=True)
        subprocess.run(git + ["-C", str(work), "push", "-q", "origin", "main", tag], check=True, capture_output=True)
    print(f"반입 도구 올림: {ADMIN}/{name} {tag}")


def main():
    for _ in range(60):
        try:
            urllib.request.urlopen(GITEA + "/api/healthz", timeout=2)
            break
        except OSError:
            time.sleep(1)
    gitea = ["/opt/kit/bin/gitea", "--work-path", str(DATA / "gitea"), "--config", str(DATA / "gitea/custom/conf/app.ini")]
    users = subprocess.run(gitea + ["admin", "user", "list", "--admin"], capture_output=True, text=True, check=True).stdout
    if ADMIN not in users.split():
        subprocess.run(gitea + ["admin", "user", "create", "--admin", "--username", ADMIN, "--email", f"{ADMIN}@kit.local",
                                "--password", os.environ["PORTAL_ADMIN_PASSWORD"], "--must-change-password=false"], check=True)
        print("관리자 계정 생성:", ADMIN)
    try:   # 실패해도 포털 로그인(OAuth2 앱)은 이어서 맞춘다 — 다음 시작 때 다시 시도
        publish_tool("mcp-remote", "원격 MCP 서버를 stdio 로 잇는 다리 — 사내 반입본(의존성 포함)")
    except Exception as e:
        print("반입 도구 올리기 실패:", e, getattr(e, "stderr", b"")[-500:] if isinstance(getattr(e, "stderr", None), bytes) else "")
    redirect = os.environ["KIT_PUBLIC_URL"].rstrip("/") + "/auth/callback"
    if OAUTH_FILE.exists() and json.loads(OAUTH_FILE.read_text()).get("redirect") == redirect \
            and json.loads(OAUTH_FILE.read_text()).get("skip_consent"):
        return
    for app in call("GET", "/api/v1/user/applications/oauth2") or []:
        if app["name"] == "kit-portal":
            call("DELETE", f"/api/v1/user/applications/oauth2/{app['id']}")
    app = call("POST", "/api/v1/user/applications/oauth2",
               {"name": "kit-portal", "redirect_uris": [redirect], "confidential_client": True,
                "skip_secondary_authorization": True})
    OAUTH_FILE.write_text(json.dumps({"client_id": app["client_id"], "client_secret": app["client_secret"], "redirect": redirect,
                                      "skip_consent": True}))
    OAUTH_FILE.chmod(0o640)  # 포털(kit 그룹)이 읽는다
    print("포털 OAuth2 앱 등록:", redirect)


if __name__ == "__main__":
    main()
