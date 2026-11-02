# 패키지 불포함형 (소스)

인터넷이 되는 빌드 PC 에서 이미지를 만듭니다. 받는 것은 모두 버전과 해시가 고정돼 있습니다(Dockerfile).

```
./build/build.sh 1.0.0          # → dist/mcp-dev-server-kit-v1.0.0.tar + SHA256SUMS
./build/build.sh 1.0.0 --zip    # zip 까지
```

- `src/server/` 서버 구성요소 · `src/devkit/` 개발자 PC 설치기(goose · srt · mcp-test) · `src/samples/` 점검용 good/bad 샘플 · `src/vendor/skillspector/` NVIDIA SkillSpector 원본(커밋 2eb84478, Apache-2.0)
- 만든 tar 로 설치하는 순서는 패키지 포함형과 같습니다.
