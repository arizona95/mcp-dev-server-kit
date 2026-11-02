# localmcp_devenv_sds

사내에서 MCP 를 만들고, 중앙에서 검사·승인한 뒤, 임직원 Claude Code 에 배포하는 개발 환경 키트입니다.

| 폴더 | 무엇이 들어 있나 |
|---|---|
| `develop_kit/package_included/` | 패키지 포함형 — 설치에 필요한 모든 것이 든 Docker 이미지 tar 1개 + SHA256SUMS. 인터넷이 없는 서버에 그대로 설치합니다. |
| `develop_kit/package_excluded/` | 패키지 불포함형 — 소스와 빌드 스크립트만. 인터넷이 되는 곳에서 `build/build.sh` 로 이미지를 직접 만듭니다. |
| `manual/` | 사내 주관리자 매뉴얼 · 임직원 개발자 매뉴얼 (docx, 실제 화면 사진 포함) |
| `governance/` | 이런 배포 패키지를 직접 만들 때 지켜야 할 정책과, 이 구현체가 그 정책을 지키는 방법 (docx) |

zip 은 아직 만들지 않았습니다. 필요할 때 이 폴더를 통째로 묶으면 됩니다.
