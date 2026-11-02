# SDSmcpDEV — mcp-dev-server-kit

사내관리자 설치 가이드: [docs/install-guide-admin.md](docs/install-guide-admin.md)

## 전제

- 사내 서버 = 리눅스 + Docker 확정. 키트 전체가 Docker 이미지 1개.
- 개발자 PC = 리눅스 또는 윈도우. 외부 인터넷 없이 사내 서버만 봄.
- MCP 호스트는 goose 하나 (리눅스용·윈도우용 두 개). 개발자가 포털 다운로드 페이지에서 받음. 페이지가 OS 를 판별해 맞는 파일을 먼저 보여 주고, 다른 OS 파일도 고를 수 있음.

## 폴더

```
src/
├── server/              # Docker 이미지 1개에 들어가는 것 (리눅스 전용)
│   ├── front/           # nginx — 바깥 포트 하나: / 포털, /git/ Gitea, /llm/ LiteLLM
│   ├── git-host/        # Gitea v28.1.0 (계정의 원본, 포털 로그인 = Gitea OAuth2)
│   ├── portal/          # 업로드 포털 · 관리자 승인 화면 · 다운로드 페이지(OS 판별)
│   ├── gate-worker/     # 중앙 검사 (osv.dev, LLM 분석)
│   ├── publisher/       # 승인 → managed-mcp.json 생성, revoked 처리
│   ├── litellm/         # LLM 등록 설정
│   ├── egress-proxy/    # 허용목록 프록시
│   ├── sandbox-images/  # 검사용 빌드·실행 이미지
│   └── kit-cli/         # init / verify / mail-template
├── devkit/              # 개발자 PC 용 (포털이 내려줌)
│   ├── hosts/goose/VERSION  # goose 버전·해시 (파일은 이미지 빌드 때 받음)
│   └── installer/       # install.sh / install.ps1 — 포털이 서버 주소·해시·사내 CA 를 채워 내려줌
└── samples/{good,bad}/  # kit verify 용
build/                   # 빌드 스크립트 → dist/ (git 제외)
```

## egress 통제

- 컨테이너 안 nftables 가 바깥 연결을 기본 차단. 바깥에 나갈 수 있는 건 squid(`proxy` 사용자) 하나뿐, 그것도 허용목록 포트만.
- squid 가 허용목록 주소만 CONNECT 허용. 키트 서비스는 `HTTPS_PROXY=http://127.0.0.1:3128`. 검사용 격리 컨테이너는 `:3129` 로.
- 허용목록 = 기본 줄(`*.osv.dev:443`, `gate.env` 의 `LLM_API_BASE` 주소) + 포털에서 더한 줄(`/data/egress/extra.json`).
- 포털(`kit` 사용자)은 목록 파일만 쓰고, 적용은 root `egress.py serve` 가 유닉스 소켓으로 받아 검증 후 수행.
- 포털 `/admin/egress`: 허용목록 추가·삭제, [검증 실행](허용 곳은 프록시로 열림 / 목록 밖·프록시 우회·IP 직접은 막힘), 바깥 연결 기록, 변경 이력, 우회 차단 누적 건수.
- 방화벽을 걸려면 `docker run` 에 **`--cap-add NET_ADMIN`** 필요 (설치 가이드 4단계에 추가할 것).

## 로그인

- 계정은 Gitea 하나. 개발자가 `/git/` 에서 가입하면 그 계정으로 포털에 로그인한다(Gitea OAuth2, 첫 로그인만 허용 화면).
- 관리자 = Gitea 관리자. 처음 기동 때 `kitadmin` / `PORTAL_ADMIN_PASSWORD` 로 만든다.

## 개발자 설치

- 포털 `/download`: OS 판별 → 개인 키 발급 → 한 줄 설치 명령 (리눅스 `curl … | sh`, 윈도우 `irm … | iex`).
- 설치하면 `mcp-test` 가 생긴다 = goose 를 `KIT_PUBLIC_URL/llm` (개인 키) 에 붙여 실행. 인자는 goose 그대로.
- `/llm/` 은 nginx 가 요청마다 포털에 개인 키를 확인하고, LiteLLM 마스터 키는 서버 안에서만 붙인다. 키 다시 발급 = 예전 키 즉시 끊김.
- 사내 CA(`/data/tls/ca.pem`)가 있으면: 리눅스는 `mcp-test` 전용 인증서 묶음(`SSL_CERT_FILE`), 윈도우는 현재 사용자 신뢰 저장소에 등록.

## gate.env

| 변수 | 예 |
|---|---|
| `KIT_PUBLIC_URL` | `https://mcp.사내도메인` |
| `PORTAL_ADMIN_PASSWORD` | 첫 관리자(kitadmin) 비밀번호 |
| `LLM_MODEL` | `anthropic/claude-haiku-4-5`, `openai/<모델>` |
| `LLM_API_BASE` | `https://api.anthropic.com` (egress 기본 허용에도 쓰임) |
| `LLM_API_KEY` | |

## 중앙 검사 (게이트)

- 순서: Gitea 저장소 → kit-mcp.json → 정적 위협 패턴(ClawVet·SkillSpector, plugSpector 이식본 그대로) → osv.dev → 격리 실행(설치 + tools/list, 실행 중 바깥 접속 기록) → LLM 의미론(SkillSpector SSD 프롬프트 그대로) → 지난 승인본과 툴·egress 비교.
- 항목마다 이유 · 코드(줄 강조) · 패치 제안(osv diff / 원본 규칙 수정 안내). critical·high 가 있으면 '차단' → 승인 불가.
- 승인 → `/approved/simple` 에 휠 · `managed-mcp.json` + Ed25519 서명. 되돌리기 → 다음 배포에서 빠짐.
- 실사 보고서: https://claude.ai/artifact/C82RTYdk7HLHLDWn6Hwngc

## 배포 묶음

`./build/build.sh 1.0.0` → `dist/mcp-dev-server-kit-v1.0.0.zip` (tar + SHA256SUMS). 설치 후 `docker exec mcp-dev-server-kit kit verify`.

## 개발용 실행

```
cd src && docker build -t mcp-dev-server-kit:dev .
docker run -d --name mcpdev-kit-test --cap-add NET_ADMIN -p 127.0.0.1:4190:8080 \
  --env-file gate.env -v mcpdev-kit-test-data:/data mcp-dev-server-kit:dev
# http://127.0.0.1:4190  (kitadmin / PORTAL_ADMIN_PASSWORD)
```
