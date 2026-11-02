"""게이트 워커 — 대기 중인 등록 요청을 하나씩 검사한다. root 로 돈다(docker.sock)."""
import json
import os
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402
import sandbox_image  # noqa: E402

DATA = Path(os.environ.get("KIT_DATA", "/data"))
REQUESTS = DATA / "registry" / "requests"
REGISTRY = DATA / "registry" / "registry.json"


def save(path, obj):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1))
    os.chown(tmp, 0, int(os.popen("getent group kit").read().split(":")[2]))
    tmp.chmod(0o660)
    tmp.replace(path)


def previous_approved(name):
    try:
        entry = json.loads(REGISTRY.read_text()).get(name)
    except FileNotFoundError:
        return None
    return entry if entry and entry.get("status") == "approved" else None


def appeal_key(f):
    hit = next((l["text"].strip() for l in f.get("snippet", []) if l.get("hit")), "")
    return (f.get("check"), f.get("rule") or f.get("title"), f.get("file"), hit)


def carry_appeals(req):
    """같은 MCP 의 지난 요청에서 허용된 소명은 같은 항목(규칙·파일·걸린 줄)에 그대로 이어 붙인다."""
    accepted = {}
    for f in sorted(REQUESTS.glob("*.json")):
        old = json.loads(f.read_text())
        if old["id"] == req["id"] or old.get("name") != req.get("name"):
            continue
        for x in (old.get("result") or {}).get("findings", []):
            if (x.get("appeal") or {}).get("status") == "accepted":
                accepted[appeal_key(x)] = {**x["appeal"], "carried_from": old["id"]}
    n = 0
    for x in (req.get("result") or {}).get("findings", []):
        a = accepted.get(appeal_key(x))
        if a:
            x["appeal"] = a
            n += 1
    return n


def main():
    REQUESTS.mkdir(parents=True, exist_ok=True)
    print("격리 이미지:", sandbox_image.ensure(), flush=True)
    while True:
        for f in sorted(REQUESTS.glob("*.json")):
            req = json.loads(f.read_text())
            if req.get("status") != "queued":
                continue
            req["status"] = "running"
            save(f, req)
            try:
                req["result"] = gate.run(req, previous_approved(req.get("name", "")), log=lambda m: print(m, flush=True))
            except Exception:
                req["result"] = {"verdict": "오류", "error": traceback.format_exc()[-2000:]}
            req["result"]["appeals_carried"] = carry_appeals(req)
            req["status"] = "done"
            save(f, req)
            print(f"[{req['id']}] {req['result'].get('verdict')}", flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
