#!/bin/sh
# MCP Dev Kit 처음 설치 — 이 묶음 폴더에서 이 파일 하나만 실행한다(관리자 · 리눅스 + Docker).
#   sudo ./install.sh
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
  echo "이미 설치돼 있습니다 — 버전 바꾸기는 포털 '버전 관리' 에서 합니다."; docker exec "$CT" kit version; exit 0
fi
echo "4/5 시작"
docker run -d --name "$CT" --restart unless-stopped --cap-add NET_ADMIN --env-file "$KIT/gate.env" \
  -p "${KIT_PUBLISH:-443:443}" -v mcp-kit-data:/data -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KIT/tls":/etc/kit/tls:ro -v "$KIT/releases":/releases:ro "$IMAGE" >/dev/null
for i in $(seq 1 60); do docker exec "$CT" kit verify --quick >/dev/null 2>&1 && break; sleep 5; done
echo "5/5 점검"
docker exec "$CT" kit verify 2>&1 | grep -v '^\[verify-' || true
echo
docker exec "$CT" kit version
echo
echo "다음: LLM 공급자 키를 키 저장소에 넣습니다 → docker exec -i $CT kit llm-key < 키파일   (그 뒤 키파일은 지웁니다)"
