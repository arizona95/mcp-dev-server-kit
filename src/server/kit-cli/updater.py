"""키트 버전 갈아끼우기 — '업데이트 담당' 컨테이너(새 버전 이미지로 따로 뜸, docker.sock)가 돈다.

지금 컨테이너는 자기 자신을 바꿀 수 없으므로, 포털의 [설치] → root 업데이트 에이전트가 새 이미지를 불러온 뒤 이 프로그램을
'kit-updater' 컨테이너로 띄운다. 데이터 볼륨(/data)을 같이 붙여 진행 상태를 /data/update/status.json 에 쓴다 —
화면은 옛 포털이든 새 포털이든 같은 파일을 읽어 진행률을 보여 준다.

단계: ① 정리(새 검사 요청 막기 · 도는 검사 끝날 때까지) ② 패치 적용 검사(데이터 사본 + 새 이미지로 미리 띄워 점검)
     ③ 백업(데이터 볼륨 통째 사본) ④ 적용(옛 컨테이너 멈추고 같은 설정으로 새 이미지) ⑤ 점검(kit verify)
     → 실패하면 새 컨테이너 지우고 백업 데이터·옛 컨테이너로 되돌림(롤백). 데이터는 같은 볼륨을 그대로 쓴다.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

D = Path("/data/update")
STATUS, FLAG = D / "status.json", D / "maintenance"
STEPS = ["정리", "패치 적용 검사", "백업", "적용", "점검"]


def docker(*a, check=True, timeout=900):
    p = subprocess.run(["docker", *a], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(a[:3])}… 실패: {(p.stderr or p.stdout)[-400:]}")
    return p.stdout.strip()


class Status:
    def __init__(self, src, dst):
        self.s = {"state": "running", "from": src, "to": dst, "started": time.time(), "steps": [{"name": n, "state": "wait"} for n in STEPS],
                  "log": []}
        self.save()

    def save(self):
        tmp = STATUS.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.s, ensure_ascii=False, indent=1))
        tmp.chmod(0o644)
        tmp.replace(STATUS)

    def step(self, i, state, detail=""):
        self.s["steps"][i].update(state=state, detail=detail, at=time.time())
        self.s["pct"] = int(100 * sum(x["state"] == "done" for x in self.s["steps"]) / len(STEPS))
        self.save()

    def log(self, m):
        self.s["log"] = (self.s["log"] + [f"{time.strftime('%H:%M:%S')} {m}"])[-60:]
        self.save()
        print(m, flush=True)


def run_args(info, image, name):
    """옛 컨테이너 설정 그대로(환경 변수 · 볼륨 · 포트 · 권한 · 재시작) 새 이미지로 docker run 인자를 만든다."""
    hc, cfg = info["HostConfig"], info["Config"]
    a = ["run", "-d", "--name", name]
    pol = hc.get("RestartPolicy", {}).get("Name")
    if pol:
        a += ["--restart", pol]
    for c in hc.get("CapAdd") or []:
        a += ["--cap-add", c]
    for b in hc.get("Binds") or []:
        a += ["-v", b]
    for m in info.get("Mounts", []):
        if m["Type"] == "volume":
            a += ["-v", f"{m['Name']}:{m['Destination']}"]
    for port, binds in (hc.get("PortBindings") or {}).items():
        for b in binds or []:
            a += ["-p", f"{(b.get('HostIp') + ':') if b.get('HostIp') else ''}{b['HostPort']}:{port.split('/')[0]}"]
    skip = ("PATH=", "KIT_VERSION=", "KIT_SANDBOX_IMAGE=", "KIT_DATA=")
    for e in cfg.get("Env") or []:
        if not e.startswith(skip):
            a += ["-e", e]
    return a + [image]


def wait_ready(name, limit=240):
    t = time.time()
    while time.time() - t < limit:
        out = docker("exec", name, "supervisorctl", "-c", "/opt/kit/server/supervisord.conf", "status", check=False)
        rows = [l.split()[:2] for l in out.splitlines() if l.strip()]
        if rows and all(s == "RUNNING" or (n == "gitea-bootstrap" and s == "EXITED") for n, s in rows):
            return True
        time.sleep(5)
    return False


def verify(name, tries=12):
    """kit verify --quick — 서비스가 RUNNING 이어도 LiteLLM 등이 포트를 여는 데 시간이 걸린다. 10초 간격으로 다시 본다."""
    out = ""
    for _ in range(tries):
        out = docker("exec", name, "kit", "verify", "--quick", check=False)
        if "[FAIL]" not in out:
            return out
        time.sleep(10)
    return out


def main():
    old, new_image, volume = os.environ["KIT_OLD"], os.environ["KIT_NEW_IMAGE"], os.environ["KIT_VOLUME"]
    src, dst = os.environ.get("KIT_FROM", "?"), os.environ.get("KIT_TO", "?")
    D.mkdir(parents=True, exist_ok=True)
    st = Status(src, dst)
    info = json.loads(docker("inspect", old))[0]
    old_image = info["Config"]["Image"]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup, pre_vol, pre_name, renamed = f"{volume}-backup-v{src}-{stamp}", f"kit-preflight-{stamp}", f"kit-preflight-{stamp}", f"{old}-v{src}"
    phase = 0
    try:
        # ① 정리 — 새 검사 요청·쓰기를 막고(포털이 이 표지를 본다), 도는 검사가 끝날 때까지
        st.step(0, "running"); FLAG.write_text(json.dumps({"to": dst, "at": time.time()}))
        t = time.time()
        while True:
            busy = [f.name for f in Path("/data/registry/requests").glob("*.json") if json.loads(f.read_text()).get("status") in ("queued", "running")]
            if not busy:
                break
            if time.time() - t > 1800:
                raise RuntimeError(f"30분이 지나도 검사가 끝나지 않았습니다: {', '.join(busy[:5])}")
            st.step(0, "running", f"도는 검사 {len(busy)}건 끝나길 기다리는 중"); time.sleep(10)
        st.step(0, "done", "새 요청 막음 · 도는 검사 없음")
        # ② 패치 적용 검사 — 데이터 사본에 새 이미지를 포트 없이 띄워 서비스·키 저장소·외부 접속 통제를 점검
        phase = 1; st.step(1, "running", "데이터 사본 만드는 중")
        docker("volume", "create", pre_vol)
        docker("run", "--rm", "-v", f"{volume}:/from:ro", "-v", f"{pre_vol}:/to", "--entrypoint", "sh", new_image, "-c", "cp -a /from/. /to/")
        # 사본에 띄울 때: 옛 설정의 환경 변수·인증서만 — 포트는 열지 않는다(지금 서비스와 겹치지 않게)
        envs = [e for e in info["Config"].get("Env") or [] if not e.startswith(("PATH=", "KIT_VERSION=", "KIT_SANDBOX_IMAGE=", "KIT_DATA="))]
        tls = [b for b in info["HostConfig"].get("Binds") or [] if b.split(":")[1:2] == ["/etc/kit/tls"]]
        pre = ["run", "-d", "--name", pre_name, "--cap-add", "NET_ADMIN", "-v", f"{pre_vol}:/data", "-v", "/var/run/docker.sock:/var/run/docker.sock"]
        for e in envs:
            pre += ["-e", e]
        for b in tls:
            pre += ["-v", b]
        docker(*pre, new_image)
        st.step(1, "running", "새 버전을 사본으로 띄워 점검 중")
        if not wait_ready(pre_name):
            raise RuntimeError("새 버전이 사본 데이터로 뜨지 않았습니다: " + docker("logs", "--tail", "20", pre_name, check=False)[-600:])
        chk = verify(pre_name)
        st.log("사전 점검:\n" + chk)
        if "실패" in chk or "[FAIL]" in chk:
            raise RuntimeError("패치 적용 검사 실패 — " + " / ".join(l for l in chk.splitlines() if "[FAIL]" in l))
        docker("rm", "-f", pre_name, check=False); docker("volume", "rm", pre_vol, check=False)
        st.step(1, "done", "사본 데이터로 새 버전 점검 통과")
        # ③ 백업 — 데이터 볼륨 통째 사본(되돌릴 곳)
        phase = 2; st.step(2, "running", backup)
        docker("volume", "create", backup)
        docker("run", "--rm", "-v", f"{volume}:/from:ro", "-v", f"{backup}:/to", "--entrypoint", "sh", new_image, "-c", "cp -a /from/. /to/")
        st.step(2, "done", f"백업 볼륨 {backup}")
        # ④ 적용 — 옛 컨테이너를 멈추고 이름을 바꿔 두고, 같은 설정으로 새 이미지를 띄운다
        phase = 3; st.step(3, "running", "옛 컨테이너 멈춤")
        docker("stop", "-t", "30", old); docker("rename", old, renamed)
        docker(*run_args(info, new_image, old))
        st.step(3, "done", f"{old_image} → {new_image}")
        # ⑤ 점검 — 새 버전이 진짜 데이터로 다 떴는지 · kit verify
        phase = 4; st.step(4, "running", "서비스 시작 기다리는 중")
        if not wait_ready(old):
            raise RuntimeError("새 버전 서비스가 뜨지 않았습니다")
        chk = verify(old)
        if (D / "test-fail-after-apply").exists():   # 롤백 시험용 — 관리자가 이 파일을 두면 적용 뒤 점검을 실패로 친다
            (D / "test-fail-after-apply").unlink()
            chk += "\n[FAIL] 롤백 시험 — /data/update/test-fail-after-apply"
        st.log("적용 뒤 점검:\n" + chk)
        if "[FAIL]" in chk:
            raise RuntimeError("적용 뒤 점검 실패 — " + " / ".join(l for l in chk.splitlines() if "[FAIL]" in l))
        st.step(4, "done", "전 항목 OK")
        docker("rm", "-f", renamed, check=False)
        olds = sorted(v for v in docker("volume", "ls", "-q", "--filter", f"name={volume}-backup-").split() if v.startswith(f"{volume}-backup-"))
        for v in olds[:-3]:   # 백업은 최근 3개만 남긴다
            docker("volume", "rm", v, check=False)
        FLAG.unlink(missing_ok=True)
        st.s.update(state="done", finished=time.time(), pct=100, message=f"v{dst} 로 바꿨습니다. 백업 볼륨 {backup} 은 지우기 전까지 남습니다.")
        st.save()
    except Exception as e:
        st.log(f"실패: {e}")
        st.step(phase, "failed", str(e)[:400])
        st.s["state"] = "rolling_back"; st.save()
        docker("rm", "-f", pre_name, check=False); docker("volume", "rm", pre_vol, check=False)
        if phase >= 3:   # 옛 컨테이너·데이터로 되돌림
            docker("rm", "-f", old, check=False)
            if phase >= 3 and backup:
                # 데이터를 백업 때로 되돌린다 — 단 /data/update(진행 상태·표지)는 지금 것을 둔다
                docker("run", "--rm", "-v", f"{backup}:/from:ro", "-v", f"{volume}:/to", "--entrypoint", "sh", new_image, "-c",
                       "find /to -mindepth 1 -maxdepth 1 ! -name update -exec rm -rf {} + && cd /from && tar cf - --exclude=./update . | (cd /to && tar xf -)",
                       check=False)
            docker("rename", renamed, old, check=False); docker("start", old, check=False)
            ok = wait_ready(old)
            st.log("롤백: 옛 버전으로 되돌림 " + ("완료" if ok else "— 서비스가 다 뜨지 않았습니다. 관리자 확인 필요"))
        # 옛 컨테이너의 데이터에 표지·상태를 남긴다(되돌린 경우 백업 복원으로 상태 파일이 덮였을 수 있어 다시 쓴다)
        D.mkdir(parents=True, exist_ok=True)
        FLAG.unlink(missing_ok=True)
        (D / "test-fail-after-apply").unlink(missing_ok=True)
        st.s.update(state="rolled_back" if phase >= 1 else "failed", finished=time.time(), message=f"적용하지 못해 v{src} 그대로입니다 — {str(e)[:300]}")
        st.save()
        sys.exit(1)


if __name__ == "__main__":
    main()
