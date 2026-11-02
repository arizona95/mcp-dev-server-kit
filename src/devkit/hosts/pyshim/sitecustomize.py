# MCP Dev Kit — 윈도우 srt 샌드박스 안 파이썬 보정 (mcp-test 가 샌드박스 안에서만 PYTHONPATH 로 넣는다)
# 윈도우 socket.socketpair() 는 127.0.0.1 임의 포트로 연결해 쌍을 만든다. srt 의 WFP 차단은 루프백도
# 허용 포트 범위(KIT_LOOPBACK_RANGE) 밖이면 막아 asyncio(= 대부분의 파이썬 MCP)가 시작하다 멈춘다.
# 그래서 쌍을 그 범위 안의 빈 포트로 만든다. 다른 플랫폼·범위 미지정이면 아무것도 바꾸지 않는다.
import os
import socket
import sys

_range = os.environ.get("KIT_LOOPBACK_RANGE", "")
if sys.platform == "win32" and "-" in _range:
    _lo, _hi = (int(v) for v in _range.split("-", 1))
    _orig = socket.socketpair

    def socketpair(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        if family not in (socket.AF_INET, getattr(socket, "AF_UNIX", None)) or type != socket.SOCK_STREAM:
            return _orig(family, type, proto)
        for port in range(_hi, _lo - 1, -1):          # srt 프록시는 범위 앞쪽을 먼저 잡는다 — 뒤에서부터 찾는다
            lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                lsock.bind(("127.0.0.1", port))
            except OSError:
                lsock.close()
                continue
            try:
                lsock.listen(1)
                csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                csock.connect(("127.0.0.1", port))
                ssock, _ = lsock.accept()
                return ssock, csock
            finally:
                lsock.close()
        raise OSError("허용된 루프백 포트 범위에 빈 포트가 없습니다 (KIT_LOOPBACK_RANGE=%s)" % _range)

    socket.socketpair = socketpair
