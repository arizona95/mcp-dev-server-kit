#!/bin/sh
# MCP Dev Kit 처음 설치 — 이 묶음 폴더에서 이 파일 하나만 실행한다(관리자 · 리눅스 + Docker).
#   sudo ./install.sh
#   sudo ./install.sh --recreate   gate.env 를 고친 뒤 적용 — 데이터는 그대로, 지금 버전 그대로 컨테이너만 다시 만든다
#                                  (지금 돌고 있는 버전의 폴더 /srv/kit/releases/<지금 버전>/ 에서 실행)
# 하는 일: 해시 확인 → 이미지 불러오기 → /srv/kit(설정·인증서·버전 폴더) 준비 → 컨테이너 시작 → 점검 → 버전표 출력
# 다음 버전: 새 묶음 폴더를 /srv/kit/releases/ 에 넣고 포털 '버전 관리' 에서 [설치] (데이터는 그대로, 실패하면 자동 롤백)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
KIT="${KIT_HOME:-/srv/kit}"
NAME="$(basename "$HERE")"
VERSION="${NAME#mcp-dev-server-kit-v}"
IMAGE="mcp-dev-server-kit:$VERSION"
CT="mcp-dev-server-kit"

command -v docker >/dev/null || { echo "Docker 가 필요합니다 (docker.io)"; exit 2; }
echo "1/5 해시 확인"
(cd "$HERE" && sha256sum -c SHA256SUMS)
echo "2/5 이미지 불러오기 ($IMAGE)"
docker load -i "$HERE/$NAME.tar" >/dev/null
echo "3/5 $KIT 준비"
mkdir -p "$KIT/releases" "$KIT/tls"
[ -d "$KIT/releases/$NAME" ] || cp -r "$HERE" "$KIT/releases/$NAME"
if [ ! -f "$KIT/gate.env" ]; then
  docker run --rm "$IMAGE" init > "$KIT/gate.env"; chmod 600 "$KIT/gate.env"
  echo "→ $KIT/gate.env 를 만들었습니다. 주소·관리자 비밀번호·LLM 모델을 채우고, TLS 인증서를 $KIT/tls/server.crt · server.key 에 둔 뒤 다시 실행하세요."
  exit 0
fi
if docker inspect "$CT" >/dev/null 2>&1; then
  if [ "${1:-}" != "--recreate" ]; then
    echo "이미 설치돼 있습니다 — 버전 바꾸기는 포털 '버전 관리' 에서, gate.env 를 고친 뒤 적용은 sudo ./install.sh --recreate"; docker exec "$CT" kit version; exit 0
  fi
  RUNNING="$(docker inspect -f '{{.Config.Image}}' "$CT")"
  if [ "$RUNNING" != "$IMAGE" ]; then
    echo "지금 도는 것은 $RUNNING 입니다 — 그 버전의 폴더($KIT/releases/mcp-dev-server-kit-v${RUNNING#*:}/)에서 실행하세요 (버전 바꾸기는 포털 '버전 관리')"; exit 2
  fi
  echo "   gate.env 적용 — 컨테이너만 다시 만듭니다 (데이터 볼륨 mcp-kit-data 는 그대로)"
  docker rm -f "$CT" >/dev/null
fi
echo "4/5 시작"
docker run -d --name "$CT" --restart unless-stopped --cap-add NET_ADMIN --env-file "$KIT/gate.env" \
  -p "${KIT_PUBLISH:-443:443}" -v mcp-kit-data:/data -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KIT/tls":/etc/kit/tls:ro -v "$KIT/releases":/releases:ro "$IMAGE" >/dev/null
# 서비스가 다 뜨고 LLM 게이트웨이가 키 상태를 적을 때까지 기다린다(처음 설치는 LLM 키가 아직 없어 전체 점검이 통과할 수 없다)
for i in $(seq 1 60); do
  docker exec "$CT" kit verify --quick 2>/dev/null | grep -q '^\[ OK \] 서비스' \
    && docker exec "$CT" test -s /dev/shm/kit-litellm/llm_key_source && break
  sleep 5
done
echo "5/5 점검"
if docker exec "$CT" grep -q '공급자 키 없음' /dev/shm/kit-litellm/llm_key_source; then
  docker exec "$CT" kit verify --quick 2>&1 | grep '^\[ OK \] 서비스' || true
  echo
  docker exec "$CT" kit version
  echo
  echo "다음 순서:"
  echo "  1) LLM 공급자 키를 키 저장소에 넣습니다 (그 뒤 키파일은 지웁니다)"
  echo "       sudo docker exec -i $CT kit llm-key < 키파일"
  echo "  2) 전체 점검"
  echo "       sudo docker exec $CT kit verify"
  echo "  3) MCP 가 PyPI 패키지를 쓰면: 사내 미러를 gate.env PYPI_INDEX_URL 에 적거나,"
  echo "     포털 '외부 접속'에서 pypi.org · files.pythonhosted.org 를 엽니다"
  exit 0
fi
docker exec "$CT" kit verify 2>&1 | grep -v '^\[verify-' || true
echo
docker exec "$CT" kit version
