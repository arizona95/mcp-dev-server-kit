"""kit — 사내관리자 명령.

  kit init            gate.env 예시를 출력 (docker run --rm mcp-dev-server-kit:<버전> init > gate.env)
  kit verify          설치 점검: 서비스 · 외부 접속 통제 · LLM tool calling · osv.dev · good 통과/bad 차단
  kit mail-template   임직원 안내 메일 문안
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
# 서버 주소 (개발자 PC 가 접속하는 주소, https 권장)
KIT_PUBLIC_URL=https://mcp.example.corp

# 첫 관리자 계정(kitadmin) 비밀번호 — Gitea·포털 공용
PORTAL_ADMIN_PASSWORD=

# 사내 데이터 반출이 승인된 LLM API (tool calling 지원 필수)
#   OpenAI 호환: LLM_MODEL=openai/<모델 이름>
#   Anthropic : LLM_MODEL=anthropic/claude-haiku-4-5
LLM_MODEL=openai/
LLM_API_BASE=https://
LLM_API_KEY=

# 사내 PyPI 미러 (있으면). 비우면 pypi.org — 그때는 외부 접속 패널에서 pypi.org·files.pythonhosted.org 를 열어야 함
PYPI_INDEX_URL=

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
    key = (DATA / "litellm" / "master_key").read_text().strip()
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


def verify():
    results = [check("서비스", services), check("외부 접속 통제", egress), check("LLM tool calling", llm_tool_calling),
               check("osv.dev 접속", osv_reach), check("good 샘플 통과 · bad 샘플 차단", samples)]
    print("전 항목 OK" if all(results) else f"실패 {results.count(False)}건")
    return 0 if all(results) else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        print(INIT, end="")
    elif cmd == "verify":
        sys.exit(verify())
    elif cmd == "mail-template":
        mail_template()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
