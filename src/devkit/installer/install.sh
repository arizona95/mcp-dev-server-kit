#!/bin/sh
# MCP Dev Kit 설치 (리눅스) — 포털 다운로드 페이지가 서버 주소·해시를 채워서 내려준다.
# 사용: curl -fsSL {{PUBLIC}}/download/install.sh | KIT_TOKEN=<개인 키> sh
set -eu
PUBLIC="{{PUBLIC}}"
FILE="{{GOOSE_FILE}}"
SHA256="{{GOOSE_SHA256}}"
: "${KIT_TOKEN:?포털 다운로드 페이지에서 개인 키를 발급받아 KIT_TOKEN 으로 넘겨 주세요}"

DIR="$HOME/.local/share/mcp-dev-kit"
BIN="$HOME/.local/bin"
CONF="$HOME/.config/mcp-dev-kit"
mkdir -p "$DIR" "$BIN" "$CONF"
chmod 700 "$CONF"

echo "goose 받는 중…"
curl -fsSL -H "Authorization: Bearer $KIT_TOKEN" -o "$DIR/$FILE" "$PUBLIC/download/files/$FILE"
echo "$SHA256  $DIR/$FILE" | sha256sum -c - >/dev/null
tar xzf "$DIR/$FILE" -C "$DIR"
[ -x "$DIR/goose" ] || { echo "goose 실행 파일이 없습니다" >&2; exit 1; }
rm -f "$DIR/$FILE"

umask 077
printf '%s\n' "$KIT_TOKEN" > "$CONF/token"
CA_PEM='{{CA_PEM}}'
if [ -n "$CA_PEM" ]; then
  # 사내 CA: 시스템 인증서 + 사내 CA 를 합친 묶음을 mcp-test 에서만 쓴다 (sudo 불필요)
  { cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null || cat /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || true; printf '%s\n' "$CA_PEM"; } > "$CONF/ca-bundle.pem"
fi

cat > "$BIN/mcp-test" <<SH
#!/bin/sh
# MCP Dev Kit — goose 를 사내 LiteLLM 에 붙여 실행. 인자는 goose 에 그대로 넘긴다.
export GOOSE_PROVIDER=openai GOOSE_MODEL=kit-llm OPENAI_HOST="$PUBLIC/llm"
export OPENAI_API_KEY="\$(cat "$CONF/token")"
export GOOSE_TELEMETRY_OFF=1 GOOSE_DISABLE_KEYRING=1
[ -f "$CONF/ca-bundle.pem" ] && export SSL_CERT_FILE="$CONF/ca-bundle.pem"
[ \$# -eq 0 ] && set -- session
exec "$DIR/goose" "\$@"
SH
chmod 755 "$BIN/mcp-test"

echo "설치 완료: $BIN/mcp-test"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "PATH 에 $BIN 을 추가해 주세요 (예: echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc)";; esac
"$BIN/mcp-test" --version
