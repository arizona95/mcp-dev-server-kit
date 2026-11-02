"""gate.env 의 LLM 값 → LiteLLM 설정 파일. 키 값은 파일에 쓰지 않고 환경 변수 이름으로만 가리킨다."""
import json
import os
import secrets
from pathlib import Path

DATA = Path(os.environ.get("KIT_DATA", "/data")) / "litellm"


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    key_file = DATA / "master_key"
    if not key_file.exists():
        key_file.write_text("sk-kit-" + secrets.token_urlsafe(32))
        key_file.chmod(0o600)
    params = {"model": os.environ["LLM_MODEL"], "api_key": "os.environ/LLM_API_KEY"}
    if os.environ.get("LLM_API_BASE"):
        params["api_base"] = os.environ["LLM_API_BASE"]
    config = {
        "model_list": [{"model_name": os.environ.get("LLM_ALIAS", "kit-llm"), "litellm_params": params}],
        "general_settings": {"master_key": "os.environ/LITELLM_MASTER_KEY"},
        "litellm_settings": {"telemetry": False},
    }
    # YAML 은 JSON 의 상위집합이라 JSON 으로 써도 LiteLLM 이 읽는다
    (DATA / "config.yaml").write_text(json.dumps(config, indent=1))


if __name__ == "__main__":
    main()
