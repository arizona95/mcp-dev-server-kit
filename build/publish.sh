#!/usr/bin/env bash
# 로컬에서 고친 SDSmcpDEV 를 공개 저장소(main)로 올린다 — 시험 서버는 거기서 git pull.
# 사용: SDSmcpDEV/build/publish.sh ["커밋 메시지"]
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
REMOTE=${KIT_PUBLIC_REMOTE:-https://github.com/arizona95/mcp-dev-server-kit.git}
if [ -n "$(git status --porcelain -- SDSmcpDEV)" ]; then
  git add -A -- SDSmcpDEV
  git commit -q -m "${1:-SDSmcpDEV: 시험 반영}" -- SDSmcpDEV
fi
git subtree split -q --prefix SDSmcpDEV -b mcpkit-public
git push -q "$REMOTE" mcpkit-public:main
echo "올림: $(git rev-parse --short mcpkit-public) → $REMOTE"
