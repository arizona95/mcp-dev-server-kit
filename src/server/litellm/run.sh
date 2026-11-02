#!/bin/sh
# kit 사용자로 실행. 바깥은 HTTPS_PROXY(squid) 로만 나간다.
set -e
export LITELLM_MASTER_KEY="$(cat /data/litellm/master_key)"
exec /opt/kit/litellm-venv/bin/litellm --config /data/litellm/config.yaml --host 127.0.0.1 --port 4000
