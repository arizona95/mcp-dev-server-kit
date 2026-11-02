#!/bin/sh
# 배포 묶음 만들기 → dist/mcp-dev-server-kit-v<버전>/ (버전 하나 = 폴더 하나)
#   mcp-dev-server-kit-v<버전>.tar  키트 이미지(검사용 격리 이미지 포함)
#   manifest.json                   버전 · 구성요소 버전표(이미지 안 kit version --json) · tar 의 sha256
#   manifest.json.sig               배포 서명 키(KIT_RELEASE_KEY, 기본 ~/.config/mcp-kit-release/release.key — 저장소 밖)로 서명
#   SHA256SUMS · install.sh        처음 설치는 install.sh 하나 · 다음 버전은 이 폴더를 서버 /srv/kit/releases/ 에 넣고 포털 '버전 관리'에서 설치
# 사용: build/build.sh <버전> [--zip]
set -eu
VERSION="${1:-1.0.0}"
ZIP="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
NAME="mcp-dev-server-kit-v$VERSION"
OUT="$ROOT/dist/$NAME"
KEY="${KIT_RELEASE_KEY:-${HOME:-/root}/.config/mcp-kit-release/release.key}"
mkdir -p "$OUT" "$SRC/images"
COMMIT=$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo "")

echo "1/4 검사용 격리 이미지"
docker build -q -t "mcp-kit-sandbox-python:$VERSION" "$SRC/server/sandbox-images/python" >/dev/null
docker save "mcp-kit-sandbox-python:$VERSION" -o "$SRC/images/sandbox-python.tar"

echo "2/4 키트 이미지 mcp-dev-server-kit:$VERSION"
docker build -q --build-arg KIT_VERSION="$VERSION" --build-arg KIT_COMMIT="$COMMIT" -t "mcp-dev-server-kit:$VERSION" "$SRC" >/dev/null

echo "3/4 묶음 폴더 $OUT"
rm -f "$OUT"/*
docker save "mcp-dev-server-kit:$VERSION" -o "$OUT/$NAME.tar"
cp "$ROOT/build/install.sh" "$OUT/install.sh" && chmod 755 "$OUT/install.sh"
docker run --rm --entrypoint /opt/kit/venv/bin/python "mcp-dev-server-kit:$VERSION" /opt/kit/server/kit-cli/version.py --json > "$OUT/components.json"
python3 - "$OUT" "$NAME" <<'PY'
import hashlib, json, sys
out, name = sys.argv[1], sys.argv[2]
h = hashlib.sha256()
with open(f"{out}/{name}.tar", "rb") as f:
    for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
m = json.load(open(f"{out}/components.json"))
m.update(image=f"{name}.tar", image_sha256=h.hexdigest())
json.dump(m, open(f"{out}/manifest.json", "w"), ensure_ascii=False, indent=1)
PY
rm -f "$OUT/components.json"
if [ -f "$KEY" ]; then
  python3 -c "
import base64, sys
from cryptography.hazmat.primitives import serialization
k = serialization.load_pem_private_key(open(sys.argv[1], 'rb').read(), None)
print(base64.b64encode(k.sign(open(sys.argv[2], 'rb').read())).decode())" "$KEY" "$OUT/manifest.json" > "$OUT/manifest.json.sig"
else
  echo "   (서명 키 없음: $KEY — 서명 없는 묶음은 '버전 관리'에서 설치할 수 없습니다)"
fi
(cd "$OUT" && sha256sum "$NAME.tar" manifest.json install.sh > SHA256SUMS)

[ "$ZIP" = "--zip" ] || { ls -la "$OUT"; exit 0; }
echo "4/4 tar(올리기용)"
(cd "$ROOT/dist" && tar cf "$NAME.kit.tar" "$NAME")
ls -la "$OUT" "$ROOT/dist/$NAME.kit.tar"
