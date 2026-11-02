#!/usr/bin/env bash
# 시험 서버에서: 공개 저장소를 당겨와 이미지를 다시 굽고 컨테이너를 바꾼 뒤 점검한다.
# 데이터(볼륨 mcp-kit-data)·설정(gate.env)·인증서(tls/)는 그대로 둔다 — 모두 git 밖.
set -euo pipefail
cd "$(dirname "$0")/.."
VER=${KIT_VERSION:-1.0.0}
git pull -q --ff-only
echo "== $(git log -1 --format='%h %s')"
./build/build.sh "$VER"
docker rm -f mcp-dev-server-kit >/dev/null 2>&1 || true
mkdir -p /srv/kit-releases
docker run -d --name mcp-dev-server-kit --restart unless-stopped --cap-add NET_ADMIN --env-file gate.env \
  -p 443:443 -v mcp-kit-data:/data -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/tls":/etc/kit/tls:ro -v /srv/kit-releases:/releases:ro \
  "mcp-dev-server-kit:$VER" >/dev/null
sleep 45
docker exec mcp-dev-server-kit kit verify 2>&1 | grep -v '^\[verify-'
