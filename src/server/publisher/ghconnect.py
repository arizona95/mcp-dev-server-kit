"""ssh ProxyCommand — 사내 egress 프록시(HTTPS_PROXY, squid)에 HTTP CONNECT 로 터널을 열고 표준 입출력과 잇는다.
컨테이너에서 바깥으로 직접 나가는 길은 nftables 가 막으므로, git push(ssh)도 허용목록(ssh.github.com:443)을 지나야 한다.
  ssh -o ProxyCommand='python3 ghconnect.py %h %p' ...
"""
import os
import select
import socket
import sys
from urllib.parse import urlparse


def main(host, port):
    proxy = urlparse(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "http://127.0.0.1:3128")
    s = socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=20)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        part = s.recv(4096)
        if not part:
            sys.exit("프록시가 연결을 끊었습니다")
        head += part
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200" not in status:
        sys.exit(f"프록시가 거절했습니다: {status} (egress 허용목록에 {host}:{port} 가 있는지 보세요)")
    s.settimeout(None)
    rest = head.split(b"\r\n\r\n", 1)[1]
    out, inp = sys.stdout.buffer, sys.stdin.buffer
    if rest:
        out.write(rest)
        out.flush()
    watch = [s, inp]
    while True:
        r, _, _ = select.select(watch, [], [])
        if s in r:
            data = s.recv(65536)
            if not data:
                return
            out.write(data)
            out.flush()
        if inp in r:
            data = os.read(inp.fileno(), 65536)
            if data:
                s.sendall(data)
            else:   # 입력이 끝났으면 서버 쪽만 마저 읽는다
                s.shutdown(socket.SHUT_WR)
                watch = [s]


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
