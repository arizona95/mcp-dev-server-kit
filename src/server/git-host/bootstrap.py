"""Gitea 가 뜬 뒤 한 번: 관리자 계정 · 포털 로그인용 OAuth2 앱. 이미 있으면 건너뛴다."""
import base64
import json
import os
import subprocess
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
