FROM debian:bookworm-slim
ARG KIT_VERSION=dev
ENV KIT_VERSION=$KIT_VERSION KIT_SANDBOX_IMAGE=mcp-kit-sandbox-python:$KIT_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      squid nftables python3 python3-venv supervisor ca-certificates git nginx \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /usr/sbin/nologin kit \
    && useradd -m -s /bin/sh git && usermod -aG kit git
RUN python3 -m venv /opt/kit/venv && /opt/kit/venv/bin/pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 itsdangerous==2.2.0 cryptography==43.0.3
RUN python3 -m venv /opt/kit/litellm-venv && /opt/kit/litellm-venv/bin/pip install --no-cache-dir "litellm[proxy]==1.104.3"
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
RUN chmod -R a+rX /opt/kit/devkit
COPY samples /opt/kit/samples
# build/build.sh 가 넣는 검사용 격리 이미지 tar (호스트에 없으면 워커가 docker load)
COPY images /opt/kit/images
COPY server /opt/kit/server
RUN ln -s /opt/kit/server/kit-cli/kit /usr/local/bin/kit
ENV KIT_DATA=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/opt/kit/server/entrypoint.sh"]
