"""Gitea 설정(app.ini) — 처음 한 번 비밀값을 만들어 /data/gitea 에 둔다. 공개 주소는 gate.env 의 KIT_PUBLIC_URL + /git/."""
import os
import secrets
from pathlib import Path

DATA = Path(os.environ.get("KIT_DATA", "/data")) / "gitea"


def secret(name, n=48):
    f = DATA / "secrets" / name
    if not f.exists():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(secrets.token_urlsafe(n))
        f.chmod(0o600)
    return f.read_text().strip()


def main():
    public = os.environ["KIT_PUBLIC_URL"].rstrip("/")
    # 회사 SSO(P5): 붙어 있으면 가입은 회사 로그인으로만, 비밀번호 로그인 창은 숨김(키트 관리자 kitadmin 은 API 용으로 남음)
    sso = bool(os.environ.get("KIT_SSO_DISCOVERY_URL"))
    service = ("ALLOW_ONLY_EXTERNAL_REGISTRATION = true\nENABLE_PASSWORD_SIGNIN_FORM = false\n" if sso else "")
    oauth2_client = ("\n[oauth2_client]\nENABLE_AUTO_REGISTRATION = true\nUSERNAME = " + os.environ.get("KIT_SSO_USERNAME", "email") + "\nACCOUNT_LINKING = auto\nUPDATE_AVATAR = false\n" if sso else "")
    (DATA / "custom" / "conf").mkdir(parents=True, exist_ok=True)
    (DATA / "custom" / "conf" / "app.ini").write_text(f"""APP_NAME = MCP Dev Kit Git
RUN_USER = git
RUN_MODE = prod
WORK_PATH = {DATA}

[server]
PROTOCOL = http
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3000
ROOT_URL = {public}/git/
DISABLE_SSH = true
OFFLINE_MODE = true
LFS_START_SERVER = false

[database]
DB_TYPE = sqlite3
PATH = {DATA}/gitea.db

[repository]
ROOT = {DATA}/repos

[security]
INSTALL_LOCK = true
SECRET_KEY = {secret("secret_key")}
INTERNAL_TOKEN = {secret("internal_token", 64)}

[oauth2]
ENABLED = true
JWT_SECRET = {secret("jwt_secret", 32)}

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = true
DEFAULT_KEEP_EMAIL_PRIVATE = true
{service}{oauth2_client}
[openid]
ENABLE_OPENID_SIGNIN = false
ENABLE_OPENID_SIGNUP = false


[cron.update_checker]
ENABLED = false

[log]
MODE = console
LEVEL = Warn
""")


if __name__ == "__main__":
    main()
