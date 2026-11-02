# goose 사내망 실측 (2026-10-29, 리눅스)

대상: goose v1.57.0 (`goose-x86_64-unknown-linux-gnu.tar.gz`, 2026-10-28 릴리스), 소스 커밋 775b3958.
경로: goose → LiteLLM(docker `litellm/litellm:main-stable`, OpenAI 형식) → Claude API(`claude-haiku-4-5`).
샘플 MCP: 툴 `secret_code(name)` → `CODE-<NAME>-7731`.

| # | 확인한 것 | 설정 | 결과 |
|---|---|---|---|
| 1 | LiteLLM 뒤에 붙여 MCP 툴 호출 (stdio) | `GOOSE_PROVIDER=openai` `OPENAI_HOST=http://…:4199` `OPENAI_API_KEY=<LiteLLM 키>` `GOOSE_MODEL=claude` | 툴 호출 → `CODE-KIM-7731` |
| 2 | 프록시를 따르는가, 다른 곳으로 나가는가 | `HTTPS_PROXY`=거부·기록 프록시, `NO_PROXY=127.0.0.1`, 텔레메트리 끄지 않음 | 프록시 기록 `CONNECT models.dev:443` 1건(거부됐지만 정상 동작). strace connect = 프록시·LiteLLM 두 곳뿐 |
| 3 | 사설 CA 인증서의 LiteLLM (HTTPS) | CA 설정 없음 | 실패 (`unknown ca`) |
| 4 | 〃 | `GOOSE_CA_CERT_PATH=ca.pem` | 성공 |
| 5 | 〃 | `SSL_CERT_FILE=ca.pem` (OS 인증서 저장소 경로) | 성공 |
| 6 | 서버에 둔 MCP (HTTPS, streamable HTTP) | `GOOSE_CA_CERT_PATH` 만 | 실패 — 툴 못 찾음, `unknown ca` |
| 7 | 〃 | `SSL_CERT_FILE=ca.pem` | 툴 호출 → `CODE-PARK-7731` |

## 결론

- LiteLLM 연결, 프록시, 사설 인증서 모두 됨.
- **사내 CA 는 OS 인증서 저장소에 넣어야 한다.** `GOOSE_CA_CERT_PATH` 는 LLM 쪽에만 적용되고 HTTP MCP 연결에는 안 먹는다(소스 `crates/goose/src/agents/extension_manager/streamable_http.rs` 의 `http_client` 가 TLS 설정을 안 받음). 리눅스는 `SSL_CERT_FILE` 로도 됨.
- 바깥으로 나가려는 것: `models.dev`(모델 목록, 15초 타임아웃, 내장 목록으로 대체). 막혀도 동작. 설치 스크립트에서 텔레메트리는 `GOOSE_TELEMETRY_OFF=1` 로 끈다.

## 아직 안 한 것

- 윈도우 실측 (`goose-x86_64-pc-windows-msvc.zip`) — 윈도우 인증서 저장소·시스템 프록시를 따르는지.
