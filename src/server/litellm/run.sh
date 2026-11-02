#!/bin/sh
# kit 사용자로 실행. 바깥은 HTTPS_PROXY(squid) 로만 나간다.
# 키는 디스크에 없다(P7): 마스터 키 = 메모리(/dev/shm/kit, 시작마다 새로) · 공급자 키 = 키 저장소(Gitea 시크릿)에서 꺼내 이 프로세스 환경에만.
set -e
export LITELLM_MASTER_KEY="$(cat /dev/shm/kit/master_key)"
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/kit-secrets.sock ] && break; sleep 1; done
# 키 저장소(Gitea)가 아직 안 떴거나 잠깐 실패하면 기다렸다 다시 — Gitea 가 멀쩡한데도 비어 있을 때만 '키 없음'
# (전엔 한 번만 물어, 시작 순서·디스크 가득 등으로 한 번 실패하면 다시 시작할 때까지 '키 없음'으로 남았다)
for i in $(seq 1 60); do
  K="$(/opt/kit/venv/bin/python /opt/kit/server/kit-secrets/agent.py kit-env KIT_LLM_API_KEY 2>/dev/null | sed -n 's/^KIT_LLM_API_KEY=//p')"
  [ -n "$K" ] && break
  /opt/kit/venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/api/healthz', timeout=3)" 2>/dev/null && [ "$i" -ge 3 ] && break
  sleep 2
done
if [ -n "$K" ]; then
  export LLM_API_KEY="$K"; echo "LLM 공급자 키: 키 저장소(Gitea 시크릿 KIT_LLM_API_KEY)" > /dev/shm/kit-litellm/llm_key_source
elif [ -n "${LLM_API_KEY:-}" ]; then
  echo "LLM 공급자 키: gate.env 평문 — kit llm-key 로 키 저장소에 옮기고 gate.env 에서 지우세요" > /dev/shm/kit-litellm/llm_key_source
else
  echo "LLM 공급자 키 없음 — kit llm-key 로 넣으세요" > /dev/shm/kit-litellm/llm_key_source
fi
unset K
exec /opt/kit/litellm-venv/bin/litellm --config /data/litellm/config.yaml --host 127.0.0.1 --port 4000
