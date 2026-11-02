"""SkillSpector(NVIDIA, vendor/skillspector, 원본 그대로)를 CLI 로 돌리고 결과 JSON 을 그대로 읽는다.

LLM 은 키트 LiteLLM(OpenAI 호환)으로: SKILLSPECTOR_PROVIDER=openai + OPENAI_BASE_URL. 바깥(osv.dev)은 HTTPS_PROXY.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

BIN = os.environ.get("KIT_SKILLSPECTOR_BIN", "/opt/kit/skillspector-venv/bin/skillspector")
DATA = Path(os.environ.get("KIT_DATA", "/data"))


def scan(root, use_llm=True):
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.json"
        env = dict(os.environ, SKILLSPECTOR_PROVIDER="openai", OPENAI_BASE_URL="http://127.0.0.1:4000/v1",
                   OPENAI_API_KEY=(DATA / "litellm" / "master_key").read_text().strip(), SKILLSPECTOR_MODEL="kit-llm",
                   SKILLSPECTOR_LOG_LEVEL="WARNING")
        cmd = [BIN, "scan", str(root), "--format", "json", "--output", str(out)] + ([] if use_llm else ["--no-llm"])
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
        if not out.exists():
            raise RuntimeError(f"skillspector 실패 (exit {p.returncode}): {(p.stderr or p.stdout)[-800:]}")
        report = json.loads(out.read_text())
        report["_warnings"] = [l for l in (p.stderr or "").splitlines() if "WARNING" in l or "ERROR" in l][-20:]
        return report
