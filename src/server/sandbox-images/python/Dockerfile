# 검사용 격리 실행 이미지 — 등록 요청된 MCP 를 설치하고 tools/list 만 받아 본다.
# 키트 이미지와 같은 Debian(다이제스트·스냅숏 고정) 위의 파이썬 3.11 — P1·P14
FROM debian:bookworm-20261005-slim@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91
# apt 도 같은 날짜의 Debian 스냅숏으로 고정(P1·P14) — 어느 날 빌드해도 같은 패키지
ARG APT_SNAPSHOT=20261005T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm-updates main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "$APT_SNAPSHOT" "$APT_SNAPSHOT" "$APT_SNAPSHOT" > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/py
ENV PATH=/opt/py/bin:$PATH
RUN useradd -m -u 1000 sandbox && mkdir /work && chown sandbox /work
COPY mcp_probe.py /opt/probe/mcp_probe.py
# kit verify 용 샘플 의존성 — 설치 직후 외부(PyPI) 없이 good/bad 샘플을 검사할 수 있게 이미지에 넣어 둔다
COPY wheelhouse.txt /opt/wheelhouse.txt
RUN pip download -q -d /opt/wheelhouse -r /opt/wheelhouse.txt && chmod -R a+rX /opt/wheelhouse
USER sandbox
WORKDIR /work
