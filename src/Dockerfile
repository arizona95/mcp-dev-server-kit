# 개발자 PC 샌드박스 srt(@anthropic-ai/sandbox-runtime) 묶음 — 리눅스·윈도우 공용 (srt-win 포함)
# 베이스 이미지는 다이제스트로 고정(P1·P14 — 공개된 지 2주가 지난 것만: node 22.12.0 = 2024-12, debian bookworm-20261005 = 2026-10-06)
FROM node:22.12.0-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213 AS srt
RUN npm install --prefix /srt-bundle --omit=dev --no-audit --no-fund @anthropic-ai/sandbox-runtime@0.0.80 \
    && rm -rf /srt-bundle/node_modules/.bin \
    && tar czf /srt-bundle.tgz -C / srt-bundle

# mcp-remote(원격 MCP 서버를 stdio 로 잇는 다리) — 의존성까지 잠금 파일 그대로(P14), 설치 스크립트 실행 안 함
FROM node:22.12.0-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213 AS mcpremote
COPY devkit/hosts/mcp-remote/package.json devkit/hosts/mcp-remote/package-lock.json /mcp-remote/
RUN cd /mcp-remote && npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM debian:bookworm-20261005-slim@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91
ARG KIT_VERSION=dev
# apt 도 같은 날짜의 Debian 스냅숏으로 고정(P1·P14) — 어느 날 빌드해도 같은 패키지
ARG APT_SNAPSHOT=20261005T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm-updates main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "$APT_SNAPSHOT" "$APT_SNAPSHOT" "$APT_SNAPSHOT" > /etc/apt/sources.list

ENV KIT_VERSION=$KIT_VERSION KIT_SANDBOX_IMAGE=mcp-kit-sandbox-python:$KIT_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      squid nftables python3 python3-venv supervisor ca-certificates git nginx openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /usr/sbin/nologin kit \
    && useradd -m -s /bin/sh git && usermod -aG kit git
# 파이썬 패키지는 하위 의존성까지 버전·해시 고정(requirements/*.lock — uv pip compile --generate-hashes --exclude-newer <2주 전>)
COPY server/requirements /opt/kit/requirements
RUN python3 -m venv /opt/kit/venv && /opt/kit/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r /opt/kit/requirements/portal.lock
RUN python3 -m venv /opt/kit/litellm-venv && /opt/kit/litellm-venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r /opt/kit/requirements/litellm.lock
ADD --checksum=sha256:ea93cfa4a300564ac457d3903469fea49ec5a4da37d0cebaa435f8e329ea64d0 \
    https://github.com/go-gitea/gitea/releases/download/v28.1.0/gitea-28.1.0-linux-amd64 /opt/kit/bin/gitea
RUN chmod 755 /opt/kit/bin/gitea
# 검사용 격리 컨테이너를 띄우는 docker CLI (download.docker.com 정적 빌드, 해시는 받아서 잰 값)
ADD --checksum=sha256:5ed6d86b5d78199eac0dbcd4d81e6de6545bc8c8a575b6efc1d4a4b292824746 \
    https://download.docker.com/linux/static/stable/x86_64/docker-28.0.1.tgz /tmp/docker.tgz
RUN tar xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker && rm /tmp/docker.tgz
ADD --checksum=sha256:ab396c95aebbd28b4d38c175234be8d4a3ea0c96e7ccb24c307e4618c9be57e1 \
    https://github.com/block/goose/releases/download/v1.54.0/goose-x86_64-unknown-linux-gnu.tar.gz /opt/kit/devkit/hosts/goose/linux-x64/
ADD --checksum=sha256:5c39bc91c3eadc231847e21a8a469e778431084437b233a63a950fee22db6239 \
    https://github.com/block/goose/releases/download/v1.54.0/goose-x86_64-pc-windows-msvc.zip /opt/kit/devkit/hosts/goose/windows-x64/
COPY devkit /opt/kit/devkit
COPY --from=srt /srt-bundle.tgz /opt/kit/devkit/hosts/srt/srt-bundle.tgz
COPY --from=mcpremote /mcp-remote/node_modules /opt/kit/devkit/hosts/mcp-remote/node_modules
RUN chmod -R a+rX /opt/kit/devkit
# SkillSpector (NVIDIA, vendor/ 원본 그대로) — Python 3.12 이상이 필요해 uv 로 따로 설치, uv.lock 그대로
COPY vendor/skillspector /opt/kit/vendor/skillspector
RUN cd /opt/kit/vendor/skillspector \
    && UV_PYTHON_INSTALL_DIR=/opt/kit/python UV_PROJECT_ENVIRONMENT=/opt/kit/skillspector-venv \
       /opt/kit/venv/bin/uv sync --frozen --no-dev --no-editable --python 3.12 \
    && chmod -R a+rX /opt/kit/python /opt/kit/skillspector-venv
COPY samples /opt/kit/samples
# build/build.sh 가 넣는 검사용 격리 이미지 tar (호스트에 없으면 워커가 docker load)
COPY images /opt/kit/images
COPY server /opt/kit/server
RUN ln -s /opt/kit/server/kit-cli/kit /usr/local/bin/kit
# 빌드 정보 — kit version · 배포 묶음 manifest 가 읽는다
ARG KIT_COMMIT=""
RUN printf '{"version":"%s","commit":"%s","built":"%s","base_image":"debian:bookworm-20261005-slim","apt_snapshot":"%s"}\n' \
      "$KIT_VERSION" "$KIT_COMMIT" "$(date -u +%Y-%m-%dT%H:%MZ)" "$APT_SNAPSHOT" > /opt/kit/BUILD.json
ENV KIT_DATA=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/opt/kit/server/entrypoint.sh"]
