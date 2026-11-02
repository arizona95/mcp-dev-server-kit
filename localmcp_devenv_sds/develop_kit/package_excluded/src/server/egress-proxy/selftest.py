"""egress 자가 점검 — 포털 [검증] 버튼과 `kit verify` 가 부른다. 키트 서비스와 같은 kit 사용자로 돈다.

각 항목은 실제로 바깥에 연결을 시도하고, 기대한 결과(허용/차단)와 실제 결과를 함께 돌려준다.
"""
import socket
import ssl
import time

PROXY = ("127.0.0.1", 3128)
BLOCK_PROBE = "example.com"
# 이름 풀기 없이 TCP 자체가 막히는지 보려는 공용 DNS 주소
BLOCK_PROBE_IP = "1.1.1.1"


def via_proxy(host, port=443, timeout=10):
    """프록시에 CONNECT 를 보내 프록시의 답 첫 줄을 돌려준다."""
    with socket.create_connection(PROXY, timeout=timeout) as s:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        status = s.recv(4096).split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200" not in status:
            return False, f"프록시 응답: {status}"
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(s, server_hostname=host) as t:
            t.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            first = t.recv(4096).split(b"\r\n", 1)[0].decode(errors="replace")
        return True, f"프록시 응답: {status} → 상대 서버 응답: {first}"


def direct(host, port=443, timeout=5):
    """프록시를 거치지 않고 바로 연결해 본다."""
    try:
        addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, family=socket.AF_INET)[0][4]
    except OSError as e:
        return False, f"이름 풀기 실패: {e}"
    try:
        with socket.create_connection(addr[:2], timeout=timeout):
            return True, f"{addr[0]}:{port} 에 바로 연결됨"
    except OSError as e:
        return False, f"{addr[0]}:{port} 바로 연결 실패: {e}"


def run(rules):
    checks = []
    def check(name, expect_open, fn, *args):
        t = time.time()
        try:
            opened, detail = fn(*args)
        except OSError as e:
            opened, detail = False, f"연결 오류: {e}"
        checks.append({"name": name, "expect": "허용" if expect_open else "차단",
                       "actual": "허용" if opened else "차단", "pass": opened == expect_open,
                       "detail": detail, "ms": int((time.time() - t) * 1000)})

    for r in rules:
        host = "osv.dev" if r["host"].startswith("*.") else r["host"]
        check(f"{host}:{r['port']} — 프록시", True, via_proxy, host, r["port"])
    check(f"{BLOCK_PROBE}:443 — 프록시, 목록 밖", False, via_proxy, BLOCK_PROBE)
    check(f"{BLOCK_PROBE}:443 — 직접", False, direct, BLOCK_PROBE)
    check(f"{BLOCK_PROBE_IP}:443 — 직접 IP", False, direct, BLOCK_PROBE_IP)
    for r in rules[:1]:
        host = "osv.dev" if r["host"].startswith("*.") else r["host"]
        check(f"{host}:{r['port']} — 직접 (허용된 곳도)", False, direct, host, r["port"])
    return checks
