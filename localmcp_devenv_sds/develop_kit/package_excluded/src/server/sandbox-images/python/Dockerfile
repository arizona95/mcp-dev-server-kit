# 검사용 격리 실행 이미지 — 등록 요청된 MCP 를 설치하고 tools/list 만 받아 본다.
FROM python:3.11-slim
RUN useradd -m -u 1000 sandbox && mkdir /work && chown sandbox /work
COPY mcp_probe.py /opt/probe/mcp_probe.py
# kit verify 용 샘플 의존성 — 설치 직후 외부(PyPI) 없이 good/bad 샘플을 검사할 수 있게 이미지에 넣어 둔다
COPY wheelhouse.txt /opt/wheelhouse.txt
RUN pip download -q -d /opt/wheelhouse -r /opt/wheelhouse.txt && chmod -R a+rX /opt/wheelhouse
USER sandbox
WORKDIR /work
