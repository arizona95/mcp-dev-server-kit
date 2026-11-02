"""egress 허용목록 — 기본 줄(gate.env) + 포털에서 더한 줄 → squid 허용 설정 + nftables 규칙.

허용목록 파일과 적용은 나눠 둔다: 포털(kit 사용자)은 extra.json 만 쓰고,
root 로 도는 `egress.py serve` 가 유닉스 소켓으로 "apply" 를 받아 검증한 뒤 적용한다.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

DATA = os.environ.get("KIT_DATA", "/data")
EGRESS = f"{DATA}/egress"
EXTRA = f"{EGRESS}/extra.json"
CHANGES = f"{EGRESS}/changes.jsonl"
ALLOW_CONF = f"{EGRESS}/allow.conf"
NFT_FILE = f"{EGRESS}/egress.nft"
# 표를 다시 만들면 nft 카운터가 0 이 되므로, 그 전까지 센 수를 여기 쌓는다
BLOCKED_BASE = f"{EGRESS}/direct_blocked_base"
SOCK = "/run/kit-egress.sock"
SQUID_CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "squid.conf")
PROXY_USER = "proxy"

HOST_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def builtin_rules():
    rules = [{"host": "*.osv.dev", "port": 443, "reason": "의존성 취약점 조회", "builtin": True}]
    llm = os.environ.get("LLM_API_BASE", "")
    if llm:
        u = urlparse(llm)
        rules.append({"host": u.hostname, "port": u.port or (443 if u.scheme == "https" else 80),
                      "reason": "LLM API", "builtin": True})
    return rules


def load_extra():
    try:
        with open(EXTRA) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def validate(rule):
    host, port = rule.get("host", ""), rule.get("port")
    if not isinstance(host, str) or not HOST_RE.match(host):
        raise ValueError(f"호스트 형식이 아님: {host!r}")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"포트 형식이 아님: {port!r}")


def all_rules():
    rules = builtin_rules() + [dict(r, builtin=False) for r in load_extra()]
    for r in rules:
        validate(r)
    return rules


def squid_domain(host):
    # squid dstdomain: ".a.b" = a.b 와 그 하위 도메인
    return "." + host[2:] if host.startswith("*.") else host


def render(rules):
    by_port = {}
    for r in rules:
        by_port.setdefault(r["port"], []).append(squid_domain(r["host"]))
    lines = []
    for port, hosts in sorted(by_port.items()):
        lines.append(f"acl allow_{port} dstdomain {' '.join(sorted(set(hosts)))}")
        lines.append(f"acl port_{port} port {port}")
        lines.append(f"http_access allow localnet CONNECT allow_{port} port_{port}")
        lines.append(f"http_access allow localnet !CONNECT allow_{port} port_{port}")
    ports = ", ".join(str(p) for p in sorted(by_port)) or "0"
    nft = f"""table inet kit_egress
delete table inet kit_egress
table inet kit_egress {{
  counter direct_blocked {{}}
  set blocked_seen {{ typeof meta skuid . ip daddr . th dport ; flags dynamic, timeout ; timeout 7d ; size 4096 ; }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    meta skuid "{PROXY_USER}" meta l4proto {{ tcp, udp }} th dport 53 accept
    meta skuid "{PROXY_USER}" tcp dport {{ {ports} }} accept
    meta nfproto ipv4 meta l4proto {{ tcp, udp }} add @blocked_seen {{ meta skuid . ip daddr . th dport }}
    counter name direct_blocked reject
  }}
}}
"""
    return "\n".join(lines) + "\n", nft


def squid_running():
    try:
        with open("/run/squid.pid") as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError):
        return False


def apply():
    rules = all_rules()
    allow, nft = render(rules)
    with open(ALLOW_CONF, "w") as f:
        f.write(allow)
    with open(NFT_FILE, "w") as f:
        f.write(nft)
    carried = blocked_base() + (live_blocked_count() or 0)
    subprocess.run(["nft", "-f", NFT_FILE], check=True)
    with open(BLOCKED_BASE, "w") as f:
        f.write(str(carried))
    if squid_running():
        subprocess.run(["squid", "-f", SQUID_CONF, "-k", "reconfigure"], check=True)
    return rules


def serve():
    """root 전용. 소켓 그룹(kit)만 apply·status 를 요청할 수 있다."""
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    os.chown(SOCK, 0, int(subprocess.check_output(["getent", "group", "kit"]).split(b":")[2]))
    os.chmod(SOCK, 0o660)
    s.listen(5)
    while True:
        c, _ = s.accept()
        with c:
            cmd = c.recv(64).strip()
            try:
                if cmd == b"apply":
                    reply = {"ok": True, "rules": len(apply())}
                elif cmd == b"status":
                    reply = {"ok": True, "direct_blocked": direct_blocked_count(), "blocked_seen": blocked_seen()}
                else:
                    reply = {"ok": False, "error": "unknown command"}
                c.sendall(json.dumps(reply).encode())
            except Exception as e:
                c.sendall(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False).encode())


def request(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(SOCK)
    s.sendall(cmd.encode())
    return json.loads(s.recv(65536) or b'{"ok": false, "error": "no reply"}')


def log_change(action, rule, who):
    with open(CHANGES, "a") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, "host": rule["host"],
                            "port": rule["port"], "reason": rule.get("reason", ""), "who": who},
                           ensure_ascii=False) + "\n")


def blocked_base():
    try:
        with open(BLOCKED_BASE) as f:
            return int(f.read().strip() or 0)
    except FileNotFoundError:
        return 0


def direct_blocked_count():
    live = live_blocked_count()
    return None if live is None else blocked_base() + live


def blocked_seen():
    """방화벽이 막은 직접 연결: 어떤 사용자가 어느 주소:포트로 나가려 했는지."""
    try:
        out = subprocess.run(["nft", "-j", "list", "set", "inet", "kit_egress", "blocked_seen"],
                             capture_output=True, text=True, timeout=5).stdout
        elems = next(i["set"] for i in json.loads(out)["nftables"] if "set" in i).get("elem", [])
    except Exception:
        return []
    users = {}
    for line in open("/etc/passwd"):
        f = line.split(":")
        users[int(f[2])] = f[0]
    seen = []
    for e in elems:
        uid, ip, port = (e["elem"]["val"] if isinstance(e, dict) and "elem" in e else e)["concat"]
        seen.append({"user": users.get(uid, str(uid)), "ip": ip, "port": port})
    return seen


def live_blocked_count():
    try:
        out = subprocess.run(["nft", "-j", "list", "counter", "inet", "kit_egress", "direct_blocked"],
                             capture_output=True, text=True, timeout=5).stdout
        for item in json.loads(out)["nftables"]:
            if "counter" in item:
                return item["counter"]["packets"]
    except Exception:
        return None


if __name__ == "__main__":
    {"apply": lambda: print(len(apply())), "serve": serve}[sys.argv[1]]()
