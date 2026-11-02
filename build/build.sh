#!/bin/sh
# 통합관리자: 배포 묶음 만들기 → dist/mcp-dev-server-kit-v<버전>.tar + SHA256SUMS (zip 은 --zip 을 줄 때만)
set -eu
VERSION="${1:-1.0.0}"
ZIP="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
DIST="$ROOT/dist"
mkdir -p "$DIST" "$SRC/images"

echo "1/4 검사용 격리 이미지"
docker build -q -t "mcp-kit-sandbox-python:$VERSION" "$SRC/server/sandbox-images/python" >/dev/null
docker save "mcp-kit-sandbox-python:$VERSION" -o "$SRC/images/sandbox-python.tar"

echo "2/4 키트 이미지 mcp-dev-server-kit:$VERSION"
docker build -q --build-arg KIT_VERSION="$VERSION" -t "mcp-dev-server-kit:$VERSION" "$SRC" >/dev/null

echo "3/4 tar · SHA256SUMS"
TAR="mcp-dev-server-kit-v$VERSION.tar"
docker save "mcp-dev-server-kit:$VERSION" -o "$DIST/$TAR"
(cd "$DIST" && sha256sum "$TAR" > SHA256SUMS)

[ "$ZIP" = "--zip" ] || { ls -la "$DIST"; cat "$DIST/SHA256SUMS"; exit 0; }
echo "4/4 zip"
(cd "$DIST" && rm -f "mcp-dev-server-kit-v$VERSION.zip" && python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_STORED, allowZip64=True) as z:
    for f in sys.argv[2:]: z.write(f)" "mcp-dev-server-kit-v$VERSION.zip" "$TAR" SHA256SUMS)
ls -la "$DIST"
cat "$DIST/SHA256SUMS"
