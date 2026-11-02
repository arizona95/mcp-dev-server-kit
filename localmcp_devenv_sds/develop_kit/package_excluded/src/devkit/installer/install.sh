#!/bin/sh
# MCP Dev Kit 설치 (리눅스) — 포털 다운로드 페이지가 서버 주소·해시를 채워서 내려준다.
# 사용: curl -fsSL {{PUBLIC}}/download/install.sh | KIT_TOKEN=<개인 키> sh
# 설치되는 것: goose · srt 샌드박스(sandbox-runtime) · mcp-test (실행할 때마다 서버 정책을 받아 srt 안에서 goose 실행)
set -eu
PUBLIC="{{PUBLIC}}"
FILE="{{GOOSE_FILE}}"
SHA256="{{GOOSE_SHA256}}"
SRT_SHA256="{{SRT_SHA256}}"
MJS_SHA256="{{MJS_SHA256}}"
: "${KIT_TOKEN:?포털 다운로드 페이지에서 개인 키를 발급받아 KIT_TOKEN 으로 넘겨 주세요}"

DIR="$HOME/.local/share/mcp-dev-kit"
BIN="$HOME/.local/bin"
CONF="$HOME/.config/mcp-dev-kit"
mkdir -p "$DIR" "$BIN" "$CONF"
chmod 700 "$CONF"

# 샌드박스(srt)에 필요한 것: Node 22.12 이상 · bubblewrap · socat · ripgrep (없으면 설치 안내만 하고 멈춘다)
missing=""
command -v node >/dev/null 2>&1 || missing="$missing nodejs(22.12 이상)"
command -v bwrap >/dev/null 2>&1 || missing="$missing bubblewrap"
command -v socat >/dev/null 2>&1 || missing="$missing socat"
command -v rg >/dev/null 2>&1 || missing="$missing ripgrep"
if [ -n "$missing" ]; then
  echo "먼저 설치해 주세요:$missing" >&2
  echo "  (예: sudo apt-get install bubblewrap socat ripgrep · Node 22 는 사내 배포본으로)" >&2
  exit 2
fi
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a==22&&b>=12)?0:1)' \
  || { echo "Node 22.12 이상이 필요합니다 (지금 $(node --version))" >&2; exit 2; }

get() {   # 파일 하나 받고 해시 확인
  curl -fsSL -H "Authorization: Bearer $KIT_TOKEN" -o "$DIR/$1" "$PUBLIC/download/files/$1"
  echo "$2  $DIR/$1" | sha256sum -c - >/dev/null
}

echo "goose 받는 중…"
get "$FILE" "$SHA256"
tar xzf "$DIR/$FILE" -C "$DIR"
[ -x "$DIR/goose" ] || { echo "goose 실행 파일이 없습니다" >&2; exit 1; }
rm -f "$DIR/$FILE"

echo "샌드박스(srt) 받는 중…"
get srt-bundle.tgz "$SRT_SHA256"
rm -rf "$DIR/srt-bundle" && tar xzf "$DIR/srt-bundle.tgz" -C "$DIR" && rm -f "$DIR/srt-bundle.tgz"
get mcp-test.mjs "$MJS_SHA256"

umask 077
printf '%s\n' "$KIT_TOKEN" > "$CONF/token"
CA_PEM='{{CA_PEM}}'
CA_BUNDLE=""
if [ -n "$CA_PEM" ]; then
  # 사내 CA: node 에는 추가 CA 로, goose 에는 시스템 인증서 + 사내 CA 묶음으로 (sudo 불필요)
  printf '%s\n' "$CA_PEM" > "$CONF/kit-ca.pem"
  { cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null || cat /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || true; printf '%s\n' "$CA_PEM"; } > "$CONF/ca-bundle.pem"
  CA_BUNDLE="$CONF/ca-bundle.pem"
fi
cat > "$CONF/kit.json" <<JSON
{"public": "$PUBLIC", "dir": "$DIR", "goose": "$DIR/goose",
 "srt_cli": "$DIR/srt-bundle/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js", "ca_bundle": "$CA_BUNDLE"}
JSON

cat > "$BIN/mcp-test" <<SH
#!/bin/sh
# MCP Dev Kit — 실행할 때마다 사내 서버 정책을 받아 srt 샌드박스 안에서 goose 를 띄운다. 인자는 goose 에 그대로.
[ -f "$CONF/kit-ca.pem" ] && export NODE_EXTRA_CA_CERTS="$CONF/kit-ca.pem"
exec node "$DIR/mcp-test.mjs" "\$@"
SH
chmod 755 "$BIN/mcp-test"

echo "설치 완료: $BIN/mcp-test"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "PATH 에 $BIN 을 추가해 주세요 (예: echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc)";; esac
"$DIR/goose" --version
