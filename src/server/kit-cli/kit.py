"""kit — 사내관리자 명령.

  kit init            gate.env 예시를 출력 (docker run --rm mcp-dev-server-kit:<버전> init > gate.env)
  kit verify          설치 점검: 서비스 · 외부 접속 통제 · LLM tool calling · osv.dev · good 통과/bad 차단
  kit mail-template   임직원 안내 메일 문안
  kit access-reset    접근제어를 '모두 허용'으로 되돌림 (IP 목록 실수로 잠겼을 때 — 서버에서 실행)
  kit sso             회사 SSO 붙이기(gate.env KIT_SSO_* + 키 저장소 KIT_SSO_CLIENT_SECRET) · kit sso --remove = 떼기
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

SERVER = Path("/opt/kit/server")
DATA = Path(os.environ.get("KIT_DATA", "/data"))

INIT = """# mcp-dev-server-kit 설정 — 값을 채운 뒤 docker run --env-file gate.env 로 넘긴다
# 서버 주소 — 개발자 PC 가 접속하는 주소. 반드시 도메인 이름(IP 안 됨)과 https.
#   개발자 PC 샌드박스(srt)는 IP·사설망 주소로 가는 연결을 프록시 밖으로 보내 막아 버린다.
KIT_PUBLIC_URL=https://mcp.example.corp

# 첫 관리자 계정(kitadmin) 비밀번호 — Gitea·포털 공용
PORTAL_ADMIN_PASSWORD=

# 사내 데이터 반출이 승인된 LLM API (tool calling 지원 필수)
#   OpenAI 호환: LLM_MODEL=openai/<모델 이름>
#   Anthropic : LLM_MODEL=anthropic/claude-haiku-4-5
LLM_MODEL=openai/
LLM_API_BASE=https://
# 공급자 키는 여기 적지 않는다(디스크에 평문으로 남음) — 컨테이너를 띄운 뒤 키 저장소에 넣는다:
#   docker exec -i mcp-dev-server-kit kit llm-key < 키파일   (그 뒤 키파일은 지운다)

# 사내 PyPI 미러 (있으면). 비우면 pypi.org — 그때는 외부 접속 패널에서 pypi.org·files.pythonhosted.org 를 열어야 함
PYPI_INDEX_URL=

# 회사 로그 시스템(SIEM) — HTTP 수집 주소(Splunk HEC 형식). 비우면 보내지 않음. 수집 토큰은 `kit secret KIT_SIEM_TOKEN` 으로 키 저장소에.
# SIEM 주소는 포털 '서버 외부 접속' 에서 열어 주세요.
KIT_SIEM_URL=
# 회사 SSO(OIDC) — 붙이면 회사 계정으로만 가입·로그인(이름·이메일이 회사 계정 그대로 = 게시자 신원). 적은 뒤 kit sso
#   클라이언트 비밀은 kit secret KIT_SSO_CLIENT_SECRET 으로 키 저장소에. 리다이렉트 URI = <KIT_PUBLIC_URL>/git/user/oauth2/<KIT_SSO_NAME>/callback
KIT_SSO_NAME=corp-sso
KIT_SSO_DISCOVERY_URL=
KIT_SSO_CLIENT_ID=
# Gitea 사용자 이름을 IdP 의 어느 값에서: email(@ 앞 — 기본) · preferred_username · nickname · userid
KIT_SSO_USERNAME=email
# IdP 그룹 이름 — 이 그룹 사람은 주관리자(비우면 주관리자는 kitadmin 만). 로그인할 때마다 IdP 그룹대로 다시 맞춘다
KIT_SSO_ADMIN_GROUP=
# 소속(부서)으로 쓸 IdP 그룹 이름들(쉼표로) — 로그인할 때마다 Gitea 조직 KIT_SSO_DEPT_ORG 의 같은 이름 팀으로 맞추고, 게시자 신원(P18)에 소속으로 남긴다
#   팀 이름은 영문·숫자·-·_·. 만(Gitea 규칙). 예: KIT_SSO_DEPT_GROUPS=security-team,platform-team
KIT_SSO_DEPT_GROUPS=
KIT_SSO_DEPT_ORG=corp
# 그룹 목록이 담긴 IdP 값 이름과, 그 값을 받으려고 더 요청할 scope(쉼표로 — IdP 에 따라 groups 등)
KIT_SSO_GROUP_CLAIM=groups
KIT_SSO_SCOPES=

# 기기 인증서(P6): required 이면 포털·Git 화면은 회사가 발급한 기기 인증서(kit device-cert issue <PC이름>)가 있는 PC 에서만 열린다
KIT_DEVICE_CERT=off

# 감사 기록 보존 기간(일)
KIT_LOG_RETENTION_DAYS=365

# 승인 팀 이름 (안내 메일에 들어감)
KIT_APPROVER_TEAM=보안팀
"""


def env_public():
    return os.environ.get("KIT_PUBLIC_URL", "").rstrip("/")


def mail_template():
    pub = env_public()
    team = os.environ.get("KIT_APPROVER_TEAM", "보안팀")
    print(f"""제목: [안내] 사내 MCP 개발 서버 사용 방법

안녕하세요, {team}입니다.
사내에서 MCP 를 만들고 Claude Code 에 등록하는 개발 서버를 열었습니다.

1. 계정 만들기: {pub}/git/user/sign_up
2. 테스트 도구(goose) 설치: {pub}/download
   - 화면에서 개인 키를 발급받고, 나오는 한 줄 명령을 터미널(리눅스) 또는 PowerShell(윈도우)에 붙여 넣으세요.
   - 설치 후 `mcp-test` 로 내 MCP 를 사내 LLM 에 붙여 시험할 수 있습니다.
3. 코드 올리기: {pub}/git/ 에 저장소를 만들고 push 하세요.
   - 저장소 최상위에 kit-mcp.json (name · entry · egress) 과 requirements.txt (== 로 버전 고정) 가 필요합니다.
4. 등록 요청: {pub}/mcp 에서 저장소를 고르고 [검사 요청]
   - 중앙 검사(정적 위협 패턴 · 의존성 취약점 · 격리 실행 · LLM 의미론 검사) 결과를 같은 화면에서 볼 수 있습니다.
   - 걸린 항목마다 이유 · 코드 위치 · 패치 제안이 나옵니다.
5. {team} 승인 후 Claude Code 에 자동으로 배포됩니다.

문의: {team}
""")


# ── verify ──────────────────────────────────────────────────────────

def check(name, fn):
    t = time.time()
    try:
        detail = fn()
        print(f"[ OK ] {name} — {detail} ({time.time() - t:.1f}s)", flush=True)
        return True
    except Exception as e:
        print(f"[FAIL] {name} — {type(e).__name__}: {e}", flush=True)
        return False


def services():
    out = subprocess.run(["supervisorctl", "-c", str(SERVER / "supervisord.conf"), "status"], capture_output=True, text=True).stdout
    rows = [l.split()[:2] for l in out.splitlines() if l.strip()]
    bad = [n for n, s in rows if s not in ("RUNNING",) and not (n == "gitea-bootstrap" and s == "EXITED")]
    if bad:
        raise RuntimeError("멈춘 서비스: " + ", ".join(bad))
    return ", ".join(n for n, _ in rows)


def egress():
    sys.path.insert(0, str(SERVER / "egress-proxy"))
    import egress as eg
    import selftest
    res = selftest.run(eg.all_rules())
    bad = [c["name"] for c in res if not c["pass"]]
    if bad:
        raise RuntimeError("기대와 다름: " + ", ".join(bad))
    return f"{len(res)}개 시도 모두 기대대로 (열린 곳 {len(eg.all_rules())}곳)"


def llm_tool_calling():
    key = Path("/dev/shm/kit/master_key").read_text().strip()
    body = {"model": "kit-llm", "temperature": 0, "messages": [{"role": "user", "content": "What is the weather in Seoul? Use the tool."}],
            "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Get weather for a city",
                                                        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]}
    req = urllib.request.Request("http://127.0.0.1:4000/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        msg = json.loads(r.read())["choices"][0]["message"]
    calls = msg.get("tool_calls") or []
    if not calls:
        raise RuntimeError("tool_calls 없음: " + str(msg.get("content"))[:120])
    return f"{calls[0]['function']['name']}({calls[0]['function']['arguments']})"


def osv_reach():
    sys.path.insert(0, str(SERVER / "gate-worker"))
    import osv
    hits, _ = osv.query("pyyaml==5.3.1\n")
    if not hits:
        raise RuntimeError("pyyaml 5.3.1 에 취약점이 안 나옴")
    return f"pyyaml==5.3.1 → {', '.join(h['id'] for h in hits)}"


def samples():
    sys.path.insert(0, str(SERVER / "gate-worker"))
    import gate
    import sandbox_image
    sandbox_image.ensure()
    out = []
    for name, want in (("good", "통과"), ("bad", "차단")):
        r = gate.run({"id": f"verify-{name}-{int(time.time())}", "path": f"/opt/kit/samples/{name}"})
        if r["verdict"] != want:
            raise RuntimeError(f"{name} 샘플이 '{r['verdict']}' (기대 '{want}') {r.get('error', '')}")
        out.append(f"{name}={r['verdict']}({len(r.get('findings', []))}건)")
    return " · ".join(out)


def key_store():
    """P7: 디스크에 평문 키가 없고, 공급자 키를 키 저장소에서 꺼냈는가."""
    src = Path("/dev/shm/kit-litellm/llm_key_source").read_text().strip()
    if Path("/data/litellm/master_key").exists():
        raise RuntimeError("디스크에 예전 평문 마스터 키(/data/litellm/master_key)가 남아 있습니다")
    if not src.startswith("LLM 공급자 키: 키 저장소("):
        raise RuntimeError(src)
    return src + " · 마스터 키는 메모리(/dev/shm)에만"


def put_secret(name):
    """표준 입력의 값을 키 저장소(키트 관리자 계정의 Gitea 시크릿 <name>)에 넣는다 — 화면·로그에 값을 찍지 않는다."""
    import base64
    import urllib.request
    key = sys.stdin.readline().strip()
    if not key:
        sys.exit(f"표준 입력으로 값을 넣어 주세요 (예: docker exec -i <컨테이너> kit secret {name} < 값파일)")
    user, pw = os.environ.get("KIT_ADMIN_USER", "kitadmin"), os.environ["PORTAL_ADMIN_PASSWORD"]
    req = urllib.request.Request(f"http://127.0.0.1:3000/api/v1/user/actions/secrets/{name}", method="PUT",
                                 data=json.dumps({"data": key}).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=15) as r:
        print(f"키 저장소에 넣었습니다 ({name}):", r.status)


def llm_key():
    """공급자 키를 키 저장소(KIT_LLM_API_KEY)에 넣고 LiteLLM 을 다시 띄운다."""
    put_secret("KIT_LLM_API_KEY")
    subprocess.run(["supervisorctl", "-c", str(SERVER / "supervisord.conf"), "restart", "litellm"], check=False)
    time.sleep(3)
    print(Path("/dev/shm/kit-litellm/llm_key_source").read_text().strip())
    if os.environ.get("LLM_API_KEY"):   # 옛 방식으로 gate.env 에 평문 키를 적어 둔 서버만
        print("이제 gate.env 의 LLM_API_KEY 줄을 지우고 컨테이너를 다시 만드세요.")
    else:
        print("다음: sudo docker exec mcp-dev-server-kit kit verify")


def gitea_api(method, path, body=None):
    import base64
    user, pw = os.environ.get("KIT_ADMIN_USER", "kitadmin"), os.environ["PORTAL_ADMIN_PASSWORD"]
    req = urllib.request.Request("http://127.0.0.1:3000/api/v1" + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"null")


def dept_teams(org, depts):
    """소속 팀을 담을 Gitea 조직·팀을 만든다(있으면 그대로). 팀은 저장소 권한 없이 소속 표시용."""
    import urllib.error
    try:
        gitea_api("GET", f"/orgs/{org}")
    except urllib.error.HTTPError:
        gitea_api("POST", "/orgs", {"username": org, "full_name": "소속 (회사 SSO 그룹)", "visibility": "private"})
        print(f"소속 조직을 만들었습니다: {org}")
    have = {t["name"] for t in gitea_api("GET", f"/orgs/{org}/teams?limit=200")}
    for g in depts:
        if g not in have:
            gitea_api("POST", f"/orgs/{org}/teams", {"name": g, "description": "회사 SSO 그룹 — 로그인할 때마다 맞춤", "permission": "read",
                                                     "includes_all_repositories": False, "units": ["repo.code"]})
            print(f"소속 팀을 만들었습니다: {org}/{g}")


GITEA_CLI = ["runuser", "-u", "git", "--", "env", "HTTPS_PROXY=http://127.0.0.1:3128", "HTTP_PROXY=http://127.0.0.1:3128",
             "NO_PROXY=127.0.0.1,localhost", "/opt/kit/bin/gitea", "--work-path", "/data/gitea", "--config", "/data/gitea/custom/conf/app.ini", "admin", "auth"]


def sso_remove():
    """회사 SSO 떼기 — Gitea 의 SSO 로그인 단추(인증 소스)와 kit sso 가 연 IdP 외부 접속을 지운다.
    비밀번호 로그인 화면은 gate.env 의 KIT_SSO_DISCOVERY_URL 을 비우고 install.sh --recreate 하면 돌아온다. SSO 로 만들어진 계정은 그대로 둔다."""
    name = os.environ.get("KIT_SSO_NAME", "corp-sso")
    listing = subprocess.run(GITEA_CLI + ["list"], capture_output=True, text=True).stdout
    row = next((l.split() for l in listing.splitlines()[1:] if len(l.split()) > 1 and l.split()[1] == name), None)
    if row:
        p = subprocess.run(GITEA_CLI + ["delete", "--id", row[0]], capture_output=True, text=True)
        if p.returncode == 0:
            print(f"SSO 로그인을 지웠습니다: {name}")
        elif "still used" in (p.stderr + p.stdout):   # SSO 로 만들어진 계정이 있으면 Gitea 가 지우지 않는다 — 끄기만 된다(화면)
            print(f"SSO 로 만들어진 계정이 있어 지우지 않았습니다. 끄려면 kitadmin 으로 사내 Git 의 Admin Settings → Identity & Access → "
                  f"Authentication Sources → {name} 편집에서 'This Authentication Source is Activated' 를 끄고 [Update Authentication Source]. "
                  "그 계정들이 비밀번호로 들어오게 하려면 User Accounts 에서 계정을 편집해 인증 소스를 Local 로 바꾸고 비밀번호를 정합니다")
        else:
            print("실패: " + (p.stderr or p.stdout)[-300:])
    else:
        print(f"SSO 로그인 {name} 이 없습니다")
    sys.path.insert(0, str(SERVER / "egress-proxy"))
    import egress as eg
    keep = [r for r in eg.load_extra() if r.get("reason") != "회사 SSO(IdP) — kit sso"]
    for r in [r for r in eg.load_extra() if r.get("reason") == "회사 SSO(IdP) — kit sso"]:
        Path(eg.EXTRA).write_text(json.dumps(keep, ensure_ascii=False, indent=1))
        eg.apply()
        eg.log_change("remove", r, "kit sso --remove")
        print(f"외부 접속 허용을 지웠습니다: {r['host']}:{r['port']} (회사 SSO)")
    if os.environ.get("KIT_SSO_DISCOVERY_URL"):
        print("gate.env 의 KIT_SSO_DISCOVERY_URL 을 비우고 install.sh --recreate 하면 비밀번호 로그인 화면이 돌아옵니다")


def sso():
    """회사 SSO(OIDC)를 Gitea 로그인에 붙인다 — gate.env 의 KIT_SSO_* + 키 저장소의 KIT_SSO_CLIENT_SECRET. 다시 실행하면 값을 고쳐 쓴다."""
    if "--remove" in sys.argv:
        return sso_remove()
    sys.path.insert(0, str(SERVER / "kit-secrets"))
    import agent
    disc, cid = os.environ.get("KIT_SSO_DISCOVERY_URL", ""), os.environ.get("KIT_SSO_CLIENT_ID", "")
    if not disc or not cid:
        sys.exit("gate.env 에 KIT_SSO_DISCOVERY_URL · KIT_SSO_CLIENT_ID 를 적어 주세요")
    sec = agent.request({"cmd": "kit", "names": ["KIT_SSO_CLIENT_SECRET"]}).get("values", {}).get("KIT_SSO_CLIENT_SECRET")
    if not sec:
        sys.exit("클라이언트 비밀을 먼저 키 저장소에: docker exec -i <컨테이너> kit secret KIT_SSO_CLIENT_SECRET < 파일")
    name = os.environ.get("KIT_SSO_NAME", "corp-sso")
    # IdP 는 키트 밖 — 외부 접속 허용목록에 넣는다(바깥은 Squid 로만 나간다). 이유·이력이 패널에 남는다.
    import urllib.parse
    sys.path.insert(0, str(SERVER / "egress-proxy"))
    import egress as eg
    u = urllib.parse.urlparse(disc)
    rule = {"host": u.hostname.lower(), "port": u.port or (443 if u.scheme == "https" else 80), "reason": "회사 SSO(IdP) — kit sso"}
    if not any(x["host"] == rule["host"] and x["port"] == rule["port"] for x in eg.all_rules()):
        eg.validate(rule)
        Path(eg.EXTRA).write_text(json.dumps(eg.load_extra() + [rule], ensure_ascii=False, indent=1))
        eg.apply()
        eg.log_change("add", rule, "kit sso")
        print(f"외부 접속 허용: {rule['host']}:{rule['port']} (회사 SSO)")
    gitea = GITEA_CLI
    listing = subprocess.run(gitea + ["list"], capture_output=True, text=True).stdout
    row = next((l.split() for l in listing.splitlines()[1:] if len(l.split()) > 1 and l.split()[1] == name), None)
    opts = ["--name", name, "--provider", "openidConnect", "--key", cid, "--secret", sec, "--auto-discover-url", disc,
            "--scopes", "openid", "--scopes", "email", "--scopes", "profile", "--skip-local-2fa"]
    for sc in filter(None, (x.strip() for x in os.environ.get("KIT_SSO_SCOPES", "").split(","))):
        opts += ["--scopes", sc]
    opts += ["--full-name-claim-name", "name"]   # 실명 = IdP 의 name 값
    admin_g = os.environ.get("KIT_SSO_ADMIN_GROUP", "")
    depts = [x.strip() for x in os.environ.get("KIT_SSO_DEPT_GROUPS", "").split(",") if x.strip()]
    if admin_g or depts:
        opts += ["--group-claim-name", os.environ.get("KIT_SSO_GROUP_CLAIM") or "groups"]
    if admin_g:   # IdP 의 이 그룹 = 주관리자(Gitea 관리자)
        opts += ["--admin-group", admin_g]
    if depts:     # IdP 그룹 = 소속 — 같은 이름의 Gitea 팀으로(그룹에서 빠지면 팀에서도 빠진다)
        org = os.environ.get("KIT_SSO_DEPT_ORG") or "corp"
        dept_teams(org, depts)
        opts += ["--group-team-map", json.dumps({g: {org: [g]} for g in depts}), "--group-team-map-removal"]
    cmd = gitea + (["update-oauth", "--id", row[0]] if row else ["add-oauth"]) + opts
    p = subprocess.run(cmd, capture_output=True, text=True)
    print(("SSO 를 고쳤습니다: " if row else "SSO 를 붙였습니다: ") + name if p.returncode == 0 else "실패: " + (p.stderr or p.stdout)[-400:].replace(sec, "***"))


def verify():
    if "--quick" in sys.argv:   # 업데이트 사전·사후 점검 — 오래 걸리는 샘플 검사·osv 는 뺀다
        results = [check("서비스", services), check("키 저장소 (디스크에 평문 키 없음)", key_store), check("외부 접속 통제", egress),
                   check("LLM tool calling", llm_tool_calling)]
        print("전 항목 OK" if all(results) else f"실패 {results.count(False)}건")
        return 0 if all(results) else 1
    results = [check("서비스", services), check("키 저장소 (디스크에 평문 키 없음)", key_store), check("외부 접속 통제", egress), check("LLM tool calling", llm_tool_calling),
               check("osv.dev 접속", osv_reach), check("good 샘플 통과 · bad 샘플 차단", samples)]
    print("전 항목 OK" if all(results) else f"실패 {results.count(False)}건")
    return 0 if all(results) else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        print(INIT, end="")
    elif cmd == "verify":
        sys.exit(verify())
    elif cmd == "version":   # 구성요소 버전표
        os.execv("/opt/kit/venv/bin/python", ["/opt/kit/venv/bin/python", str(SERVER / "kit-cli" / "version.py"), *sys.argv[2:]])
    elif cmd == "device-cert":   # 기기 인증서(P6) 발급·폐기
        os.execv("/opt/kit/venv/bin/python", ["/opt/kit/venv/bin/python", str(SERVER / "kit-cli" / "devcert.py"), *sys.argv[2:]])
    elif cmd == "llm-key":
        llm_key()
    elif cmd == "sso":
        sso()
    elif cmd == "secret" and len(sys.argv) > 2 and sys.argv[2] in ("KIT_SIEM_TOKEN", "KIT_SSO_CLIENT_SECRET"):
        put_secret(sys.argv[2])
    elif cmd == "mail-template":
        mail_template()
    elif cmd == "access-reset":
        p = DATA / "portal" / "access.json"
        a = json.loads(p.read_text()) if p.exists() else {"entries": []}
        a.update(mode="all", by="kit access-reset", at=time.time())
        p.write_text(json.dumps(a, ensure_ascii=False, indent=1))
        sys.path.insert(0, str(SERVER / "egress-proxy"))
        import egress
        print("접근제어: 모두 허용으로 되돌렸습니다", egress.request("access"))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
