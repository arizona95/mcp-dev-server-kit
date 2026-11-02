"""중앙 검사(게이트) — 등록 요청 하나를 받아 검사 결과를 만든다.

검사 순서: 저장소 가져오기 → kit-mcp.json → SkillSpector(NVIDIA 원본 그대로: 정적·YARA·MCP·행위·LLM 의미론·OSV)
→ osv.dev 의존성(고칠 버전 diff) → 격리 실행(설치 + tools/list, 실행 중 바깥 접속 시도 기록) → 지난 승인본과 툴·egress 비교.

결과의 각 항목 = 왜 걸렸는지(설명) · 코드(파일·줄·주변) · 패치 제안(diff 또는 SkillSpector 의 remediation).
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
import skillspector_run

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


# ── 1. SkillSpector (원본 그대로) ───────────────────────────────────────

def skillspector_findings(root):
    """SkillSpector issues 를 화면 항목으로 옮긴다. 판단·설명·수정 안내는 SkillSpector 것 그대로."""
    report = skillspector_run.scan(root)
    out = []
    for i in report.get("issues", []):
        loc = i.get("location") or {}
        explain = i.get("explanation", "")
        if i.get("finding"):
            explain += f"\n\n걸린 내용: {i['finding'].strip()}"
        title = i.get("pattern") or f"{i.get('category') or '분류 없음'} ({i.get('id')})"
        out.append(finding("skillspector", (i.get("severity") or "").lower(), title, explain,
                           loc.get("file"), loc.get("start_line"), root,
                           {"kind": "advice", "text": i["remediation"]} if i.get("remediation") else None,
                           category=i.get("category"), rule=f"skillspector:{i.get('id')}", confidence=i.get("confidence")))
    return out, report


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
    # rug pull 방지(P16): 설치된 의존성의 정확한 버전(lock)과 그 휠(리눅스·윈도우 × 파이썬 3.11~3.13)을 검사 때 받아 둔다 —
    # 승인하면 이 휠들만 승인 저장소에 올라가고, 임직원 PC 는 그 저장소만 본다(PyPI 를 보지 않음)
    deps = "" if offline else (
        "pip freeze --path /work/.deps | grep -v ' @ ' | grep -vi \"^$OWNRE==\" > /work/dist/lock.txt || true; "
        "for plat in manylinux2014_x86_64 win_amd64; do for v in 3.11 3.12 3.13; do "
        f"pip download -q --disable-pip-version-check --no-deps --only-binary=:all: --platform $plat --python-version $v --implementation cp -d /work/dist {source}-r /work/dist/lock.txt 1>&2 "
        "|| while read -r l; do [ -n \"$l\" ] || continue; "
        f"pip download -q --disable-pip-version-check --no-deps --only-binary=:all: --platform $plat --python-version $v --implementation cp -d /work/dist {source}\"$l\" 1>&2 "
        "|| echo \"DEP_MISS $plat $v $l\"; done < /work/dist/lock.txt; done; done; echo DEP_LOCK; cat /work/dist/lock.txt; echo DEP_LOCK_END; ")
    script = (f"set -e; cp -r /work/src /work/build; {install} 1>&2; {wheel} 1>&2; "
              "OWN=$(ls /work/dist/*.whl | head -1 | xargs basename | cut -d- -f1); OWNRE=$(echo $OWN | sed 's/[-_.]/[-_.]/g'); echo OWN_WHEEL=$(ls /work/dist/*.whl | head -1 | xargs basename); "
              f"{deps}PYTHONPATH=/work/.deps PATH=/work/.deps/bin:$PATH python /opt/probe/mcp_probe.py {entry}")
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
    own, lock, misses, in_lock = None, [], [], False
    for line in stdout.splitlines():
        if line.startswith("OWN_WHEEL="):
            own = line.split("=", 1)[1].strip()
        elif line == "DEP_LOCK":
            in_lock = True
        elif line == "DEP_LOCK_END":
            in_lock = False
        elif in_lock and "==" in line:
            lock.append(line.strip())
        elif line.startswith("DEP_MISS "):
            misses.append(line[9:].strip())
    for line in stdout.splitlines():
        if line.startswith('{"probe_start"'):
            probe_start = json.loads(line)["probe_start"]
        elif line.startswith("PROBE_RESULT "):
            result = json.loads(line[len("PROBE_RESULT "):])
    result["install_log"] = stderr[-3000:]
    result.update(own_wheel=own, deps_lock=lock, deps_missing=misses)
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


# ── 4. 감시자 (P17) ─────────────────────────────────────────────────
# 관리자가 포털에서 정한 목록(/data/portal/watchers.json). 기본 셋(SkillSpector·osv·격리 실행)은 끌 수 없고 수준만 바꾼다.
# 수준: 필수 = 막는 심각도(critical·high)가 하나라도 있으면 승인 불가, 감시자가 실패하면 '오류' / 심화 = 결과만 보여 주고 막지 않음.
# 추가 감시자 = 사내 Docker 이미지: 네트워크 없이 소스를 /src 에 읽기 전용으로 받아 표준 출력에 {"findings":[{severity,title,explain,file,line}]}.
from watchers_conf import BUILTIN_WATCHERS, load_watchers  # noqa: E402,F401  (포털과 같은 목록 하나)


def image_watcher_findings(w, root):
    # 소스는 docker cp 로 넣는다 — 이 컨테이너 안 경로는 호스트 Docker 가 볼 수 없다(-v 로는 빈 폴더가 붙음)
    name = f"kit-watch-{w['id']}-{os.getpid()}-{int(time.time())}"
    docker("create", "--name", name, "--network", "none", "--cpus", "1", "--memory", "1g", "--pids-limit", "256", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", w["image"], *w.get("args", []))
    try:
        docker("cp", f"{root}/.", f"{name}:/src")
        p = docker("start", "-a", name, check=False, timeout=900)
    finally:
        docker("rm", "-f", name, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"exit {p.returncode}: {(p.stderr or p.stdout)[-500:]}")
    out = []
    for f in json.loads(p.stdout).get("findings", []):
        rel, line = f.get("file"), f.get("line")
        out.append(finding(w["id"], str(f.get("severity", "medium")).lower(), f.get("title", "(제목 없음)"), f.get("explain", ""),
                           rel, line if isinstance(line, int) else None, root, {"kind": "advice", "text": f["fix"]} if f.get("fix") else None,
                           rule=f"{w['id']}:{f.get('rule') or f.get('title')}"))
    return out


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
        watchers = load_watchers()
        level = {w["id"]: w["level"] for w in watchers}
        result["watchers"] = [{k: w.get(k) for k in ("id", "name", "kind", "level", "image")} for w in watchers]
        ss, ss_report = step("SkillSpector", lambda: skillspector_findings(root))
        findings += ss
        result["skillspector"] = {"risk": ss_report.get("risk_assessment"), "metadata": ss_report.get("metadata"),
                                  "warnings": ss_report.get("_warnings", [])}
        dep, _ = step("의존성 취약점 (osv.dev)", lambda: dependency_findings(root))
        findings += dep
        artifacts = DATA / "gate" / "artifacts" / req["id"]
        sandbox = step("격리 실행", lambda: sandbox_run(root, manifest, req["id"], artifacts, offline=bool(req.get("path"))))
        result["wheel"] = sandbox.get("own_wheel") or next((p.name for p in artifacts.glob("*.whl")), None)
        result["deps_lock"], result["deps_missing"] = sandbox.get("deps_lock", []), sandbox.get("deps_missing", [])
        for m in result["deps_missing"]:   # 그 플랫폼·파이썬에서는 임직원 PC 가 설치하지 못한다
            plat, ver, dep = m.split(" ", 2)
            findings.append(finding("deps", "medium", f"휠 없음: {dep} ({'윈도우' if plat.startswith('win') else '리눅스'} · 파이썬 {ver})",
                                    f"{dep} 은 {plat} · 파이썬 {ver} 용 휠이 없어 승인 저장소에 넣지 못했습니다. 그 환경의 임직원 PC 에서는 설치되지 않습니다.",
                                    "requirements.txt", None, None, {"kind": "advice", "text": "휠을 제공하는 버전으로 바꾸거나, 그 환경을 쓰지 않는다면 소명해 주세요."}))
        result["sandbox"] = {k: sandbox.get(k) for k in ("ok", "error", "server", "egress_install", "egress_runtime")}
        findings += runtime_findings(root, manifest, sandbox)
        for w in [w for w in watchers if w["kind"] == "image" and w.get("enabled", True)]:
            try:
                findings += step(f"감시자: {w['name']}", lambda w=w: image_watcher_findings(w, root))
            except Exception as e:
                if w["level"] == "필수":
                    raise RuntimeError(f"필수 감시자 '{w['name']}' 실패 — {e}")
                findings.append(finding(w["id"], "info", f"심화 감시자 실행 실패: {w['name']}", str(e)[-800:]))
        check_of = {"skillspector": "skillspector", "osv": "osv", "sandbox": "sandbox", "deps": "osv"}
        for f in findings:   # 항목마다 어느 감시자의 것이고 그 감시자가 필수인지
            f["watcher"] = check_of.get(f["check"], f["check"])
            f["level"] = level.get(f["watcher"], "필수")
        tools = sandbox.get("tools", [])
        result["review"] = tool_review(tools, manifest, previous)
        prev_lock = dict(l.split("==", 1) for l in (previous or {}).get("deps_lock", []))
        now_lock = dict(l.split("==", 1) for l in result["deps_lock"])
        result["review"]["deps"] = {"added": sorted(f"{k}=={v}" for k, v in now_lock.items() if k not in prev_lock),
                                    "removed": sorted(f"{k}=={v}" for k, v in prev_lock.items() if k not in now_lock),
                                    "changed": sorted(f"{k} {prev_lock[k]} → {v}" for k, v in now_lock.items() if k in prev_lock and prev_lock[k] != v)}
        result["tools"] = tools
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f["severity"], 5), f["check"]))
        for i, f in enumerate(findings, 1):
            f["id"] = i
        result["findings"] = findings
        sev = {f["severity"] for f in findings if f["level"] == "필수"}   # 심화 감시자의 항목은 막지 않는다
        result["verdict"] = "차단" if sev & BLOCKING else ("검토" if findings else "통과")
    except Exception as e:
        result["verdict"] = "오류"
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        result["finished"] = time.time()
        shutil.rmtree(work, ignore_errors=True)
    return result
