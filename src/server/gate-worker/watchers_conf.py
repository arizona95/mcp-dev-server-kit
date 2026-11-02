"""감시자 목록 — 게이트 워커(root)와 포털이 같은 정의를 쓴다. 관리자가 정한 값은 /data/portal/watchers.json."""
import json
import os
from pathlib import Path

DATA = Path(os.environ.get("KIT_DATA", "/data"))
WATCHERS = DATA / "portal" / "watchers.json"
BUILTIN_WATCHERS = [{"id": "skillspector", "name": "SkillSpector (NVIDIA)", "kind": "builtin", "level": "필수", "enabled": True},
                    {"id": "osv", "name": "의존성 취약점 (osv.dev)", "kind": "builtin", "level": "필수", "enabled": True},
                    {"id": "sandbox", "name": "격리 실행 (바깥 접속 관측)", "kind": "builtin", "level": "필수", "enabled": True}]


def load_watchers():
    try:
        saved = {w["id"]: w for w in json.loads(WATCHERS.read_text())["watchers"]}
    except (FileNotFoundError, ValueError, KeyError):
        saved = {}
    out = [{**b, **{k: saved[b["id"]][k] for k in ("level",) if b["id"] in saved}} for b in BUILTIN_WATCHERS]
    out += [w for w in saved.values() if w.get("kind") == "image"]
    return out


