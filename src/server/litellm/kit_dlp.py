"""LLM 게이트웨이 정규식 차단(P20) — LiteLLM pre-call 훅. 패턴은 포털이 고치는 /data/portal/dlp.json(바뀌면 다음 요청부터).

개발자 경로(nginx /llm/ — X-Kit-User 머리가 붙음)로 온 요청만 본다. 검사기(SkillSpector)가 키트 안에서 직접 부르는 호출은
검사 대상 코드에 키가 들어 있을 수 있어 막지 않는다. 막으면 /data/litellm/dlp.jsonl 에 누가·어느 패턴인지만 남긴다(값은 안 남김).
"""
import json
import os
import re
import time

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

CONF = "/data/portal/dlp.json"
LOG = "/data/litellm/dlp.jsonl"


class KitDlp(CustomLogger):
    def __init__(self):
        super().__init__()
        self._mtime, self._pats = None, []

    def patterns(self):
        try:
            m = os.stat(CONF).st_mtime
        except FileNotFoundError:
            return []
        if m != self._mtime:
            with open(CONF) as f:
                conf = json.load(f)
            self._pats = [(p["id"], p["name"], re.compile(p["regex"])) for p in conf.get("patterns", []) if p.get("enabled")]
            self._mtime = m
        return self._pats

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        headers = {k.lower(): v for k, v in ((data.get("proxy_server_request") or {}).get("headers") or {}).items()}
        user = headers.get("x-kit-user")
        if not user:
            return data
        text = json.dumps({k: data.get(k) for k in ("messages", "input", "prompt", "system", "tools") if data.get(k) is not None},
                          ensure_ascii=False)
        for pid, name, rx in self.patterns():
            if rx.search(text):
                with open(LOG, "a") as f:
                    f.write(json.dumps({"ts": time.time(), "user": user, "pattern": pid, "name": name, "model": data.get("model")},
                                       ensure_ascii=False) + "\n")
                raise HTTPException(status_code=400, detail=f"사내 정책으로 막았습니다 — 질의에 '{name}' 모양의 비밀값이 있습니다. 지우고 다시 보내 주세요.")
        return data


proxy_handler_instance = KitDlp()
