"""중앙 검사(게이트) — 등록 요청 하나를 받아 검사 결과를 만든다.

검사 순서: 저장소 가져오기 → kit-mcp.json → 정적 위협 패턴(ClawVet·SkillSpector 원본) → osv.dev 의존성
→ 격리 실행(설치 + tools/list, 실행 중 바깥 접속 시도 기록) → 의미론 LLM 검사(SkillSpector SSD 프롬프트 원본)
→ 지난 승인본과 툴·egress 비교.

결과의 각 항목 = 왜 걸렸는지(설명) · 코드(파일·줄·주변) · 패치 제안(diff 또는 원본 규칙의 수정 안내).
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import osv
from rules import semantic_scan, threat_scan
from rules.skillspector_pattern_defaults import DEFAULT_EXPLANATIONS, DEFAULT_REMEDIATIONS, PATTERN_NAMES

DATA = Path(os.environ.get("KIT_DATA", "/data"))
GITEA = "http://127.0.0.1:3000"
SANDBOX_IMAGE = os.environ["KIT_SANDBOX_IMAGE"]
SANDBOX_NET = "mcp-kit-sandbox"
ACCESS_LOG = DATA / "egress" / "access.log"
BLOCKING = {"critical", "high"}   # 이 심각도가 하나라도 있으면 '차단'. 심각도 값은 각 규칙 원본의 것.


# ── 공통 ──────────────────────────────────────────────────────────────

def snippet(root, rel, line, around=3):
    try:
        lines = (root / rel).read_text(errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(1, line - around), min(len(lines), line + around)
    return [{"n": n, "text": lines[n - 1], "hit": n == line} for n in range(lo, hi + 1)]


def finding(check, severity, title, explain, rel=None, line=None, root=None, patch=None, **extra):
    return {"check": check, "severity": severity, "title": title, "explain": explain,
            "file": rel, "line": line, "snippet": snippet(root, rel, line) if root and rel and line else [],
            "patch": patch or {"kind": "none"}, **extra}


# ── 1. 정적 위협 패턴 ──────────────────────────────────────────────────

def skillspector_rule(name):
    """SkillSpector 패턴 이름 → upstream 규칙 id (예: TP3_MALICIOUS_URL → TP3). 표시용 연결(배선)."""
    if name in DEFAULT_EXPLANATIONS:
        return name
    head = name.split("_", 1)[0]
    return head if head in DEFAULT_EXPLANATIONS else None


def static_findings(root):
    out = []
    for f in threat_scan._scan(str(root))["findings"]:
        rel, _, ln = f["location"].rpartition(":")
        line = int(ln) if ln.isdigit() else None
        if f["source"] == "clawvet":
            explain, fix, rule = f["title"], f["fix"], f["pattern"]
        else:
            rule = skillspector_rule(f["pattern"])
            explain = DEFAULT_EXPLANATIONS.get(rule, "") if rule else ""
            fix = DEFAULT_REMEDIATIONS.get(rule, "") if rule else ""
        title = PATTERN_NAMES.get(rule, f["title"]) if f["source"] == "skillspector" and rule else f["title"]
        out.append(finding("static", f["severity"], title, explain, rel, line, root,
                           {"kind": "advice", "text": fix} if fix else None,
                           category=f["category"], rule=f"{f['source']}:{f['pattern']}", cwe=f["cwe"], match=f["match"]))
    return out


# ── 2. 의존성 (osv.dev) ────────────────────────────────────────────────

def dependency_findings(root):
    req = root / "requirements.txt"
    if not req.exists():
        return [finding("osv", "medium", "requirements.txt 없음", "의존성을 확인할 수 없습니다. 고정 버전(==)으로 적은 requirements.txt 가 필요합니다.")], []
    text = req.read_text()
    hits, loose = osv.query(text)
    out = [finding("osv", "medium", f"버전 고정 안 됨: {s}", "버전을 고정하지 않으면 검사한 것과 다른 버전이 설치될 수 있습니다.",
                   "requirements.txt", n, root, {"kind": "advice", "text": "== 로 버전을 고정해 주세요."}) for n, s in loose]
    # 패키지마다: 모든 advisory 를 고치는 가장 낮은 버전으로 올리는 diff
    by_pkg = {}
    for h in hits:
        by_pkg.setdefault((h["line"], h["package"], h["version"]), []).append(h)
    lines = text.splitlines()
    for (line, pkg, ver), vulns in by_pkg.items():
        fixes = [v["fixed"] for v in vulns if v["fixed"]]
        target = max(fixes, key=osv._version_key) if fixes else None
        patch = None
        if target:
            old = lines[line - 1]
            patch = {"kind": "diff", "text": f"--- a/requirements.txt\n+++ b/requirements.txt\n@@ -{line} +{line} @@\n-{old}\n+{pkg}=={target}\n"}
        ids = ", ".join(v["id"] + (f" ({', '.join(a for a in v['aliases'] if a.startswith('CVE'))})" if any(a.startswith('CVE') for a in v["aliases"]) else "") for v in vulns)
        explain = f"{pkg} {ver} 에 알려진 취약점 {len(vulns)}건: {ids}.\n" + "\n".join(f"· {v['id']}: {v['summary'] or v['details'][:200]}" for v in vulns)
        out.append(finding("osv", "high", f"취약한 의존성 {pkg}=={ver}", explain, "requirements.txt", line, root, patch,
                           advisories=[{"id": v["id"], "aliases": v["aliases"], "summary": v["summary"], "fixed": v["fixed"]} for v in vulns]))
    return out, hits


# ── 3. 격리 실행 ──────────────────────────────────────────────────────

def docker(*args, check=True, timeout=600):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout)


def self_ip_on_sandbox_net():
    me = os.uname().nodename
    nets = json.loads(docker("inspect", me, "--format", "{{json .NetworkSettings.Networks}}").stdout)
    if SANDBOX_NET not in nets:
        docker("network", "inspect", SANDBOX_NET, check=False).returncode == 0 or docker("network", "create", "--internal", SANDBOX_NET)
        docker("network", "connect", SANDBOX_NET, me)
        nets = json.loads(docker("inspect", me, "--format", "{{json .NetworkSettings.Networks}}").stdout)
    return nets[SANDBOX_NET]["IPAddress"]


def proxy_log_since(ip, since):
    out = []
    try:
        for line in ACCESS_LOG.read_text().splitlines():
            p = line.split()
            if len(p) >= 5 and p[1] == ip and float(p[0]) >= since:
                out.append({"ts": float(p[0]), "result": p[2], "method": p[3], "target": p[4]})
    except FileNotFoundError:
        pass
    return out


def sandbox_run(root, manifest, req_id, artifacts, offline=False):
    proxy = f"http://{self_ip_on_sandbox_net()}:3129"
    name = f"kit-gate-{req_id}"
    entry = manifest.get("entry", "")
    pip_index = os.environ.get("PYPI_INDEX_URL", "")
    if offline:   # kit verify: 이미지에 든 샘플 의존성만
        source = "--no-index --find-links /opt/wheelhouse "
    else:
        source = f"--index-url {pip_index} " if pip_index else ""
    install = "pip install --no-cache-dir --disable-pip-version-check -q --target /work/.deps " + source + "/work/build"
    wheel = "pip wheel --no-deps --disable-pip-version-check -q -w /work/dist " + source + "/work/build"
    # /work/src 는 docker cp 로 들어와 root 소유 → 쓰기 가능한 사본에서 빌드
    script = f"set -e; cp -r /work/src /work/build; {install} 1>&2; {wheel} 1>&2; PYTHONPATH=/work/.deps PATH=/work/.deps/bin:$PATH python /opt/probe/mcp_probe.py {entry}"
    docker("rm", "-f", name, check=False)
    docker("create", "--name", name, "--network", SANDBOX_NET, "--cpus", "1", "--memory", "768m", "--pids-limit", "256",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "-e", f"HTTPS_PROXY={proxy}", "-e", f"HTTP_PROXY={proxy}", "-e", f"https_proxy={proxy}", "-e", f"http_proxy={proxy}",
           SANDBOX_IMAGE, "sh", "-c", script)
    try:
        docker("cp", f"{root}/.", f"{name}:/work/src")
        ip = None
        started = time.time()
        r = subprocess.Popen(["docker", "start", "-a", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(50):
            ip = json.loads(docker("inspect", name, "--format", "{{json .NetworkSettings.Networks}}").stdout).get(SANDBOX_NET, {}).get("IPAddress") or ip
            if ip:
                break
            time.sleep(0.1)
        stdout, stderr = r.communicate(timeout=600)
        artifacts.mkdir(parents=True, exist_ok=True)
        docker("cp", f"{name}:/work/dist/.", str(artifacts), check=False)
        subprocess.run(["chmod", "-R", "a+rX", str(artifacts)], check=False)
    finally:
        docker("rm", "-f", name, check=False)
    probe_start = float("inf")   # probe 가 시작 못 했으면 모든 접속은 설치 단계
    result = {"ok": False, "error": "probe 결과 없음", "stderr": stderr[-2000:]}
    for line in stdout.splitlines():
        if line.startswith('{"probe_start"'):
            probe_start = json.loads(line)["probe_start"]
        elif line.startswith("PROBE_RESULT "):
            result = json.loads(line[len("PROBE_RESULT "):])
    result["install_log"] = stderr[-3000:]
    time.sleep(1)
    attempts = proxy_log_since(ip, started) if ip else []
    result["egress_install"] = [a for a in attempts if a["ts"] < probe_start]
    result["egress_runtime"] = [a for a in attempts if a["ts"] >= probe_start]
    return result


def grep_line(root, needle):
    """needle 이 처음 나오는 (파일, 줄). 실행 중 접속 시도를 코드 위치에 잇는 데 쓴다."""
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in (".py", ".js", ".ts", ".json", ".md", ".toml"):
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if needle in line:
                    return str(p.relative_to(root)), n
    return None, None


def runtime_findings(root, manifest, run):
    out = []
    if not run.get("ok"):
        out.append(finding("sandbox", "high", "격리 실행 실패", f"설치하거나 tools/list 를 받지 못했습니다: {run.get('error')}\n\n{run.get('stderr', '')[-800:]}\n\n{run.get('install_log', '')[-800:]}"))
    declared = {h.lower() for h in manifest.get("egress", [])}
    seen = set()
    for a in run.get("egress_runtime", []):
        host = a["target"].split(":")[0].lower()
        if host in declared or a["target"] in seen:
            continue
        seen.add(a["target"])
        rel, line = grep_line(root, host)
        out.append(finding("sandbox", "high", f"선언 안 한 바깥 접속 시도: {a['target']}",
                           f"격리 실행 중 이 MCP 가 {a['target']} 로 나가려 했습니다(프록시 결과 {a['result']}). kit-mcp.json 의 egress 에 없는 곳입니다. "
                           "회사 밖으로 데이터를 보내는 코드일 수 있습니다.", rel, line, root,
                           {"kind": "advice", "text": f"필요 없는 접속이면 코드를 지우고, 필요하면 kit-mcp.json 의 \"egress\" 에 \"{host}\" 를 적어 관리자 승인을 받으세요."}))
    return out


# ── 4. 의미론 LLM 검사 ────────────────────────────────────────────────

class LiteLLM:
    def __init__(self):
        self.key = (DATA / "litellm" / "master_key").read_text().strip()

    def complete(self, prompt):
        body = {"model": "kit-llm", "messages": [{"role": "user", "content": prompt}], "temperature": 0}
        req = urllib.request.Request("http://127.0.0.1:4000/v1/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]


def semantic_findings(root, tools):
    """README 등 문서와 툴 설명(tools/list 그대로)을 SkillSpector 의미론 검사에 넣는다."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".md", ".txt") and p.name != "requirements.txt":
                (d / p.relative_to(root)).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(p, d / p.relative_to(root))
        lines = []
        for t in tools:
            lines.append(f"## tool: {t.get('name')}")
            lines += (t.get("description") or "").splitlines()
            for k, v in (t.get("inputSchema", {}).get("properties") or {}).items():
                if v.get("description"):
                    lines.append(f"- param {k}: {v['description']}")
        (d / "tools-list.md").write_text("\n".join(lines))
        r = semantic_scan._semantic(str(d), llm=LiteLLM())
    out = []
    for f in r["findings"]:
        rel, _, ln = f["location"].rpartition(":")
        line = int(ln) if ln.isdigit() else None
        if rel == "tools-list.md":
            # 툴 설명은 코드 안 docstring 에서 온다 → 그 문장이 있는 실제 파일로 잇는다
            text = ("\n".join(lines).splitlines()[line - 1] if line and line <= len(lines) else "").strip()
            src_rel, src_line = grep_line(root, text) if text and not text.startswith("## tool") else (None, None)
            rel, line = (src_rel, src_line) if src_rel else (None, None)
        out.append(finding("semantic", f["severity"], f"{f['title']} (의미론)", f.get("description", ""), rel, line, root,
                           category="semantic_security", rule=f"skillspector:{f['pattern']}", cwe=f["cwe"]))
    return out, r.get("errors", [])


# ── 5. 지난 승인본과 비교 ─────────────────────────────────────────────

def tool_review(tools, manifest, previous):
    prev_tools = {t["name"]: t for t in (previous or {}).get("tools", [])}
    review = []
    for t in tools:
        ann = t.get("annotations") or {}
        flags = []
        if ann.get("destructiveHint"):
            flags.append("삭제·파괴")
        if ann.get("readOnlyHint") is not True:
            flags.append("쓰기 가능(읽기 전용 표시 없음)")
        if t["name"] not in prev_tools:
            flags.append("새 툴")
        elif (prev_tools[t["name"]].get("description") or "") != (t.get("description") or ""):
            flags.append("설명 바뀜")
        review.append({"name": t["name"], "description": t.get("description", ""), "annotations": ann, "flags": flags,
                       "previous_description": prev_tools.get(t["name"], {}).get("description")})
    removed = [n for n in prev_tools if n not in {t["name"] for t in tools}]
    prev_egress = set((previous or {}).get("egress", []))
    egress = set(manifest.get("egress", []))
    return {"tools": review, "removed": removed,
            "egress": {"now": sorted(egress), "added": sorted(egress - prev_egress), "removed": sorted(prev_egress - egress)}}


# ── 전체 ──────────────────────────────────────────────────────────────

def clone(repo, ref, dest):
    user, pw = os.environ.get("KIT_ADMIN_USER", "kitadmin"), os.environ["PORTAL_ADMIN_PASSWORD"]
    url = f"http://{user}:{urllib.request.quote(pw, safe='')}@127.0.0.1:3000/{repo}.git"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", ref, url, str(dest)], check=True, capture_output=True, timeout=120)
    commit = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    shutil.rmtree(dest / ".git")
    return commit


def run(req, previous=None, log=print):
    work = Path(tempfile.mkdtemp(prefix="gate-"))
    root = work / "src"
    result = {"started": time.time(), "steps": []}
    try:
        def step(name, fn):
            t = time.time()
            log(f"[{req['id']}] {name}…")
            try:
                v = fn()
                result["steps"].append({"name": name, "ok": True, "sec": round(time.time() - t, 1)})
                return v
            except Exception as e:
                result["steps"].append({"name": name, "ok": False, "sec": round(time.time() - t, 1), "error": f"{type(e).__name__}: {e}"})
                raise

        if req.get("path"):   # kit verify: 이미지 안 샘플 폴더
            result["commit"] = step("저장소 가져오기", lambda: (shutil.copytree(req["path"], root), "local")[1])
        else:
            result["commit"] = step("저장소 가져오기", lambda: clone(req["repo"], req["ref"], root))
        mf = root / "kit-mcp.json"
        if not mf.exists():
            raise ValueError("저장소 최상위에 kit-mcp.json 이 없습니다")
        manifest = json.loads(mf.read_text())
        result["manifest"] = manifest
        findings = []
        findings += step("정적 위협 패턴", lambda: static_findings(root))
        dep, _ = step("의존성 취약점 (osv.dev)", lambda: dependency_findings(root))
        findings += dep
        artifacts = DATA / "gate" / "artifacts" / req["id"]
        sandbox = step("격리 실행", lambda: sandbox_run(root, manifest, req["id"], artifacts, offline=bool(req.get("path"))))
        result["wheel"] = next((p.name for p in artifacts.glob("*.whl")), None)
        result["sandbox"] = {k: sandbox.get(k) for k in ("ok", "error", "server", "egress_install", "egress_runtime")}
        findings += runtime_findings(root, manifest, sandbox)
        tools = sandbox.get("tools", [])
        sem, sem_err = step("의미론 검사 (LLM)", lambda: semantic_findings(root, tools))
        findings += sem
        result["semantic_errors"] = sem_err
        result["review"] = tool_review(tools, manifest, previous)
        result["tools"] = tools
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f["severity"], 5), f["check"]))
        for i, f in enumerate(findings, 1):
            f["id"] = i
        result["findings"] = findings
        sev = {f["severity"] for f in findings}
        result["verdict"] = "차단" if sev & BLOCKING else ("검토" if findings else "통과")
    except Exception as e:
        result["verdict"] = "오류"
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        result["finished"] = time.time()
        shutil.rmtree(work, ignore_errors=True)
    return result
