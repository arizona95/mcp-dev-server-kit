# mcp-remote (사내 반입본)

원격 MCP 서버(https 주소)를 stdio MCP 처럼 쓰게 이어 주는 도구입니다.
의존성(`node_modules`)까지 이 저장소에 들어 있어, 인터넷 없이 받아 바로 씁니다.
출처·버전·해시는 [SOURCE.md](SOURCE.md) 에 있습니다.

## 받기 (개발자 PC — 윈도우)

```
git clone https://<사내 MCP 포털 주소>/git/kitadmin/mcp-remote.git %USERPROFILE%\mcp-remote
```

## 쓰기 — 내 PC 에서 시험하기(mcp-test)

```
mcp-test --with-extension "node %USERPROFILE%\mcp-remote\node_modules\mcp-remote\dist\proxy.js https://<원격 MCP 주소>/mcp"
```

- 원격 MCP 주소는 샌드박스 네트워크 정책에 허용돼 있어야 연결됩니다(관리자에게 요청).
- 원격 서버가 로그인(OAuth)을 요구하면 브라우저 로그인 창이 열립니다.
