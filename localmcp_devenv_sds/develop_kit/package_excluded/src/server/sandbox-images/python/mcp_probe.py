"""MCP 서버를 stdio 로 띄워 initialize → tools/list 를 받고 JSON 한 줄로 출력한다. 툴은 부르지 않는다."""
import json
import subprocess
import sys
import time

cmd = sys.argv[1:]
print(json.dumps({"probe_start": time.time()}), flush=True)
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def send(msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()


def recv(want_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        line = p.stdout.readline()
        if not line:
            break
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == want_id:
            return msg
    raise TimeoutError(f"no reply for id {want_id}")


result = {"ok": False}
try:
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "kit-gate", "version": "1"}}})
    init = recv(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = recv(2)
    result = {"ok": True, "server": init.get("result", {}).get("serverInfo", {}), "tools": tools.get("result", {}).get("tools", [])}
except Exception as e:
    result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
finally:
    p.kill()
    result["stderr"] = (p.stderr.read() or "")[-2000:]
print("PROBE_RESULT " + json.dumps(result), flush=True)
