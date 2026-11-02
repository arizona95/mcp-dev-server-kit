"""감사 기록 → 회사 로그 시스템(SIEM) 전송 · 보존 기간 (P12).

보내는 것(줄마다 JSON 한 건, source 로 구분):
  portal   /data/portal/events.jsonl      로그인·요청·승인·회수·소명·정책 변경·실행 토큰·비밀값(이름만)·개발 PC 실행
  llm      /data/logs/llm-access.jsonl    LLM 호출(누가·언제·크기 — 질의 내용은 남기지 않음)
  dlp      /data/litellm/dlp.jsonl        정규식 차단(패턴 이름만)
  egress   /data/egress/access.log        서버 바깥 접속(허용·차단)
  registry /data/registry/history.jsonl   배포·회수 이력
전송: HTTP(S) JSON — Splunk HEC 형식({"event":…,"sourcetype":…}) 을 기본으로, 바깥은 Squid 프록시로만(외부 접속 패널에 SIEM 주소를 열어야 함).
  KIT_SIEM_URL   예: https://splunk.corp:8088/services/collector/event   (비우면 보내지 않고 보존 기간만 지킨다)
  수집 토큰       키 저장소(키트 관리자 Gitea 시크릿 KIT_SIEM_TOKEN) — 파일·gate.env 에 두지 않는다
보존: KIT_LOG_RETENTION_DAYS(기본 365) 보다 오래된 줄은 하루 한 번 지운다. 어디까지 보냈는지는 /data/siem/offsets.json.
"""
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/opt/kit/server/kit-secrets")
DATA = Path(os.environ.get("KIT_DATA", "/data"))
SOURCES = {"portal": DATA / "portal" / "events.jsonl", "llm": DATA / "logs" / "llm-access.jsonl", "dlp": DATA / "litellm" / "dlp.jsonl",
           "egress": DATA / "egress" / "access.log", "registry": DATA / "registry" / "history.jsonl"}
STATE = DATA / "siem" / "offsets.json"
STATUS = DATA / "siem" / "status.json"
URL = os.environ.get("KIT_SIEM_URL", "").strip()
RETENTION = int(os.environ.get("KIT_LOG_RETENTION_DAYS", "365"))
PROXY = os.environ.get("KIT_SIEM_PROXY", "http://127.0.0.1:3128")


def token():
    try:
        import agent
        return agent.request({"cmd": "kit", "names": ["KIT_SIEM_TOKEN"]}).get("values", {}).get("KIT_SIEM_TOKEN", "")
    except Exception:
        return ""


def ts_of(src, line):
    try:
        if src == "egress":
            return float(line.split()[0])
        j = json.loads(line)
        return float(j.get("ts") or j.get("time") or 0)
    except (ValueError, IndexError, TypeError):
        return 0.0


def send(batch, tok):
    body = "\n".join(json.dumps({"time": t, "host": os.environ.get("KIT_PUBLIC_URL", "mcp-dev-kit"), "source": f"mcp-dev-kit:{s}",
                                 "sourcetype": "_json", "event": e}, ensure_ascii=False) for s, t, e in batch).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={"Content-Type": "application/json", **({"Authorization": f"Splunk {tok}"} if tok else {})})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    with opener.open(req, timeout=20) as r:
        return r.status


def forward_once(state, tok):
    sent = 0
    for src, path in SOURCES.items():
        if not path.exists():
            continue
        st = path.stat()
        pos = state.get(src, {})
        off = pos.get("off", 0) if pos.get("ino") == st.st_ino and pos.get("off", 0) <= st.st_size else 0   # 파일이 바뀌거나 줄었으면 처음부터
        with open(path, "rb") as f:
            f.seek(off)
            chunk = f.read(2_000_000)
        lines = chunk.split(b"\n")
        if not chunk.endswith(b"\n"):
            lines = lines[:-1]          # 끝이 덜 쓰인 줄은 다음에
        batch = []
        for raw in lines:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            try:
                ev = json.loads(line) if src != "egress" else {"line": line}
            except ValueError:
                ev = {"line": line}
            batch.append((src, ts_of(src, line), ev))
        consumed = sum(len(x) + 1 for x in lines)
        if batch:
            send(batch, tok)
            sent += len(batch)
        state[src] = {"ino": st.st_ino, "off": off + consumed}
    return sent


def trim_old():
    """보존 기간보다 오래된 줄을 지운다 — 원자적으로 바꿔 쓴다."""
    cut = time.time() - RETENTION * 86400
    removed = 0
    for src, path in SOURCES.items():
        if not path.exists():
            continue
        lines = path.read_bytes().split(b"\n")
        keep = [l for l in lines if not l.strip() or ts_of(src, l.decode(errors="replace")) == 0 or ts_of(src, l.decode(errors="replace")) >= cut]
        if len(keep) != len(lines):
            removed += len(lines) - len(keep)
            st = path.stat()
            tmp = path.with_name(path.name + ".trim")
            tmp.write_bytes(b"\n".join(keep))
            os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, st.st_mode & 0o777)
            tmp.replace(path)
    return removed


def main():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    last_trim = 0
    while True:
        status = {"at": time.time(), "url": URL, "retention_days": RETENTION}
        if URL:
            try:
                status["sent"] = forward_once(state, token())
                status["ok"] = True
                STATE.write_text(json.dumps(state))
            except Exception as e:
                status.update(ok=False, error=f"{type(e).__name__}: {e}"[:300])
        if time.time() - last_trim > 86400:
            status["trimmed"] = trim_old()
            last_trim = time.time()
            # 줄인 파일은 위치가 달라진다 — 보낸 곳까지 다시 맞춘다(이미 보낸 것은 다시 안 보냄: 끝으로)
            for src, path in SOURCES.items():
                if path.exists() and src in state:
                    state[src] = {"ino": path.stat().st_ino, "off": min(state[src]["off"], path.stat().st_size) if status.get("trimmed") == 0 else path.stat().st_size}
            STATE.write_text(json.dumps(state))
        prev = json.loads(STATUS.read_text()) if STATUS.exists() else {}
        status["total_sent"] = prev.get("total_sent", 0) + status.get("sent", 0)
        STATUS.write_text(json.dumps(status))
        time.sleep(10)


if __name__ == "__main__":
    main()
