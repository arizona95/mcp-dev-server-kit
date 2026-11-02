#!/bin/sh
# 키트 컨테이너 시작: 데이터 폴더 권한 → 허용목록 적용(nft 먼저, 서비스보다 앞) → supervisord
set -e
# docker run --rm <이미지> init  → gate.env 예시만 출력
if [ "${1:-}" = "init" ] || [ "${1:-}" = "mail-template" ]; then exec /opt/kit/server/kit-cli/kit "$@"; fi
: "${PORTAL_ADMIN_PASSWORD:?gate.env 에 PORTAL_ADMIN_PASSWORD 가 필요합니다}"
: "${LLM_MODEL:?gate.env 에 LLM_MODEL 이 필요합니다 (예: anthropic/claude-haiku-4-5, openai/<모델>)}"
# 공급자 키(LLM_API_KEY)는 키 저장소(Gitea 시크릿 KIT_LLM_API_KEY — `kit llm-key`)에 둔다. gate.env 에 남아 있으면 그것을 쓰되 경고한다.
: "${KIT_PUBLIC_URL:?gate.env 에 KIT_PUBLIC_URL 이 필요합니다 (예: https://mcp.사내도메인)}"
# 재시작이면 지난번 PID 파일이 남아 있다
rm -f /run/squid.pid /run/supervisord.pid /run/kit-egress.sock /run/kit-secrets.sock
# 메모리에만 두는 키(P7): /dev/shm(tmpfs) — 디스크에 평문 키를 남기지 않는다. LiteLLM 마스터 키는 시작할 때마다 새로.
mkdir -p /dev/shm/kit && chown root:kit /dev/shm/kit && chmod 750 /dev/shm/kit && mkdir -p /dev/shm/kit-litellm && chown kit:kit /dev/shm/kit-litellm && chmod 750 /dev/shm/kit-litellm
( umask 027; /opt/kit/venv/bin/python -c "import secrets; print('sk-kit-' + secrets.token_urlsafe(32))" > /dev/shm/kit/master_key )
chown root:kit /dev/shm/kit/master_key && chmod 640 /dev/shm/kit/master_key
rm -f /data/litellm/master_key   # 예전 판이 디스크에 남긴 평문 키
mkdir -p /data/egress /data/logs
touch /data/egress/access.log /data/egress/changes.jsonl
[ -f /data/egress/extra.json ] || echo '[]' > /data/egress/extra.json
chown proxy:kit /data/egress/access.log && chmod 640 /data/egress/access.log
chown kit:kit /data/egress/extra.json /data/egress/changes.jsonl
chown root:kit /data/egress && chmod 775 /data/egress
/opt/kit/venv/bin/python /opt/kit/server/egress-proxy/egress.py apply >/dev/null
/opt/kit/venv/bin/python /opt/kit/server/litellm/render_config.py
chown -R kit:kit /data/litellm
umask 077
sed "s|__LITELLM_MASTER_KEY__|$(cat /dev/shm/kit/master_key)|" /opt/kit/server/front/nginx.conf > /dev/shm/kit/nginx.conf
umask 022
/opt/kit/venv/bin/python /opt/kit/server/egress-proxy/egress.py access-render
# 인증서가 있으면 443 TLS, 없으면 8080 평문(개발용)
if [ -f /etc/kit/tls/server.crt ] && [ -f /etc/kit/tls/server.key ]; then
  printf 'listen 443 ssl;\nssl_certificate /etc/kit/tls/server.crt;\nssl_certificate_key /etc/kit/tls/server.key;\nssl_protocols TLSv1.2 TLSv1.3;\n' > /run/kit-nginx-listen.conf
else
  echo 'listen 8080;' > /run/kit-nginx-listen.conf
fi
/opt/kit/venv/bin/python /opt/kit/server/git-host/render_config.py
chown -R git:git /data/gitea
mkdir -p /data/portal && chown root:kit /data/portal && chmod 2770 /data/portal
mkdir -p /data/registry/requests /data/registry/approved /data/publisher /data/gate/artifacts
chown -R root:kit /data/registry /data/publisher && chmod -R g+rwX /data/registry /data/publisher
find /data/registry /data/publisher -type d -exec chmod g+s {} +
[ ! -f /data/portal/session_secret ] || chown kit:kit /data/portal/session_secret
exec /usr/bin/supervisord -c /opt/kit/server/supervisord.conf
