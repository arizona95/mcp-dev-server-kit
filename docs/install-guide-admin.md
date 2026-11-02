mcp-dev-server-kit 사내관리자 설치 가이드
2026년 10월 29일 · @dowoo
통합관리자가 보낸 이미지 파일 하나로 온프레미스 서버에 MCP 개발 서버를 설치하고, 임직원이 만든 MCP를 승인해 Claude Code에 배포하는 절차입니다. 외부로는 osv.dev와 LLM API 두 곳만 열려 있으면 됩니다.
1. 받는 것
파일 두 개가 옵니다. 서버 프로그램 전체(Git 호스트, 업로드 포털, 게이트 워커, 게시기, LiteLLM, 허용목록 프록시, 빌드·실행 이미지, 임직원용 dev-kit)가 Docker 이미지 1개에 들어 있습니다. 사내 서버는 인터넷에서 이미지를 받을 수 없으므로 이 파일을 직접 불러옵니다.
파일
전달 경로
내용
mcp-dev-server-kit-v1.0.0.tar
대용량 전송 경로 (수 GB)
전체 키트가 들어 있는 Docker 이미지 1개
SHA256SUMS
메일
이미지 파일의 체크섬
체크섬이 SHA256SUMS와 다르면 설치하지 말고 통합관리자에게 다시 요청하세요.
2. 사전 준비
온프레미스 리눅스 서버 1대에 설치합니다. 설치 전에 아래를 갖춰 두세요.
항목
요건
서버
리눅스 + Docker. 초기 권장 4 vCPU, 16GB 메모리, 200GB 디스크 (개발자 수에 따라 조정)
네트워크
사내망에서 개발자 PC가 서버에 접속 가능. 외부로는 osv.dev:443과 LLM API 주소만 허용, 나머지는 차단
LLM API
사내 데이터 반출이 승인된 OpenAI 호환 API 1개의 주소와 키. tool calling 지원 필수
도메인·인증서
서버에 쓸 사내 도메인과 TLS 인증서
사내 PyPI 미러
있으면 그 주소. 없으면 키트 내장 PyPI 저장소를 미러로 운영
외부 허용 두 곳의 용도: osv.dev는 MCP 의존성의 알려진 취약점 조회에, LLM API는 LiteLLM을 거쳐 보안 검사 분석과 개발자 대화형 테스트에 씁니다. 개발자 PC는 외부가 아니라 이 서버만 봅니다.
3. 설치 순서
서버에서 아래 순서대로 실행합니다. 어느 단계든 실패하면 멈추고 출력 내용을 통합관리자에게 보내 주세요.
1. 체크섬 확인: 두 파일을 같은 폴더에 두고 sha256sum -c SHA256SUMS. OK가 나와야 합니다.
2. 이미지 불러오기: docker load -i mcp-dev-server-kit-v1.0.0.tar
3. 설정 파일 만들기: docker run --rm mcp-dev-server-kit:1.0.0 init > gate.env로 예시를 꺼낸 뒤, LLM API 주소·키, 도메인, PyPI 미러, 승인 팀 이름을 채웁니다.
4. 실행: 아래 명령 하나로 모든 서비스가 올라가고, LiteLLM에 LLM이 등록되며, 내장 Git에 dev-kit 저장소가 생깁니다. Docker 소켓은 검사용 격리 컨테이너를 띄우는 데 씁니다.
   docker run -d --name mcp-dev-server-kit --restart unless-stopped \
     --env-file gate.env -p 443:443 \
     -v mcp-kit-data:/data -v /var/run/docker.sock:/var/run/docker.sock \
     mcp-dev-server-kit:1.0.0
5. 점검: docker exec mcp-dev-server-kit kit verify. 서비스 상태, LLM tool calling, osv.dev 접속, good 샘플 통과·bad 샘플 차단을 한 번에 확인합니다.
4. 설치 후 운영
• 임직원 안내: docker exec mcp-dev-server-kit kit mail-template이 Git 주소와 포털 주소를 채운 안내 메일 문안을 출력합니다. 그대로 개발자에게 보내면 나머지 설치와 LLM 연결은 개발자가 합니다.
• 등록 요청 승인: 포털 관리자 화면에서 대기 중인 요청을 중앙 검사 결과와 함께 보고 승인하거나 사유를 적어 반려합니다. 화면 맨 위에 뜨는 쓰기·삭제 툴, 새 툴, 바뀐 툴 설명, 외부 접속(egress) 변경을 꼭 확인하세요.
• 임직원 PC 배포: 승인되면 관리형 설정 managed-mcp.json이 자동으로 다시 만들어집니다. 이 파일을 사내 배포 도구(MDM 등)로 임직원 PC에 나눠 주면 Claude Code에 반영됩니다.
• 되돌리기: 문제가 생긴 MCP는 레지스트리에서 revoked로 바꾸면 다음 설정 배포 때 빠집니다.
• 업그레이드: 새 버전 tar를 docker load한 뒤 기존 컨테이너를 지우고 같은 docker run 명령을 새 태그로 실행합니다. 데이터와 서명 키는 mcp-kit-data 볼륨에 남고, dev-kit도 자동 갱신되어 개발자는 mcp-test self-update만 하면 됩니다.
5. 완료 확인
아래가 모두 끝나면 설치 완료입니다. 체크섬 결과와 kit verify 출력을 통합관리자에게 회신해 주세요.
[ ] SHA256SUMS 체크섬 OK
[ ] kit verify 전 항목 OK (서비스, LLM tool calling, osv.dev 접속)
[ ] good 샘플 통과, bad 샘플 차단
[ ] 개발자 안내 메일 발송
