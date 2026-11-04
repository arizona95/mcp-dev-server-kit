"""배포 자원 — 승인한 MCP 하나로 여러 배포 채널에 쓸 파일을 만든다(승인할 때마다 새로).

  <이름>-<버전>.mcpb : Claude Desktop 확장 묶음 — 관리자가 claude.ai 조직 설정 › 커넥터 › 추가 › 사용자 지정 › 데스크톱 으로 올린다
                       형식: https://github.com/modelcontextprotocol/mcpb (manifest_version 0.3)
  <이름>-<버전>.zip  : 다른 MCP 클라이언트용(Cursor·VS Code·goose·Claude Code 등) — 설정 예시 + 검사 때 고정한 휠 전부(오프라인 설치용)
  (Claude Code 플러그인 마켓플레이스는 publisher.sync_marketplace 가 저장소로 만든다)

어느 채널이든 실행 명령은 managed-mcp.json 과 같다 — uvx 가 사내 승인 저장소에서 검사 때 고정한 휠만 받는다(P16).
"""
import hashlib
import io
import json
import zipfile
from pathlib import Path

FIXED_TIME = (2026, 1, 1, 0, 0, 0)   # 같은 승인이면 같은 바이트 — 해시로 맞는 파일인지 확인할 수 있게


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, data in sorted(files.items()):
            info = zipfile.ZipInfo(rel, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data if isinstance(data, bytes) else data.encode())
    return buf.getvalue()


def _json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def mcpb_manifest(name, e, server):
    pub = e.get("publisher") or {}
    author = {"name": pub.get("name") or pub.get("login") or "MCP Dev Kit"}
    if "@" in (pub.get("email") or ""):
        author["email"] = pub["email"]
    return {
        "manifest_version": "0.3",
        "name": name,
        "display_name": name,
        "version": e["version"],
        "description": f"사내 MCP Dev Kit 에서 검사·승인된 MCP ({e['repo']}@{e['commit'][:10]})",
        "author": author,
        # 실행 파일을 묶지 않는다 — PC 의 uvx 가 사내 승인 저장소에서 고정한 휠을 받아 실행(준비물: uv)
        "server": {"type": "binary", "entry_point": "uvx",
                   "mcp_config": {"command": server["command"], "args": server["args"], "env": server["env"]}},
        "tools": [{"name": t["name"], "description": t.get("description", "")} for t in e.get("tools", [])],
        "compatibility": {"platforms": ["win32", "darwin", "linux"]},
        "keywords": ["mcp-dev-kit"],
    }


def build_mcpb(name, e, server):
    m = mcpb_manifest(name, e, server)
    readme = (f"# {name} {e['version']}\n\n{m['description']}\n\n"
              "Claude Desktop 확장 묶음입니다. 실행하면 PC 의 uvx 가 사내 승인 저장소에서 검사 때 고정한 휠만 받아 실행합니다.\n"
              "PC 준비물: uv (uvx 명령)\n")
    return _zip({"manifest.json": _json(m), "README.md": readme})


def client_configs(name, server):
    """MCP 클라이언트마다 설정 파일 모양이 조금씩 다르다 — 같은 실행 명령을 각 모양으로."""
    stdio = {"command": server["command"], "args": server["args"], "env": server["env"]}
    return {
        "configs/claude-code.mcp.json": _json({"mcpServers": {name: {"type": "stdio", **stdio}}}),
        "configs/claude_desktop_config.json": _json({"mcpServers": {name: stdio}}),
        "configs/cursor.mcp.json": _json({"mcpServers": {name: stdio}}),
        "configs/vscode.mcp.json": _json({"servers": {name: {"type": "stdio", **stdio}}}),
        "configs/goose.yaml": (f"extensions:\n  {name}:\n    type: stdio\n    enabled: true\n    cmd: {server['command']}\n"
                               f"    args: {json.dumps(server['args'])}\n    envs: {json.dumps(server['env'])}\n    timeout: 300\n"),
    }


def build_zip(name, e, server, approved_dir, norm):
    files = client_configs(name, server)
    lock = e.get("lock") or [{"file": e["wheel"], "sha256": e["sha256"]}]
    for x in lock:   # 오프라인 설치용 — 검사 때 고정한 휠 그대로(해시 확인)
        p = Path(approved_dir) / norm(x["file"].split("-")[0]) / x["file"]
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != x["sha256"]:
            raise ValueError(f"{x['file']} 해시가 승인 때와 다릅니다")
        files[f"wheels/{x['file']}"] = data
    files["kit-lock.json"] = _json({"name": name, "version": e["version"], "repo": e["repo"], "commit": e["commit"], "lock": lock})
    files["README.md"] = f"""# {name} {e['version']}

사내 MCP Dev Kit 에서 검사·승인된 MCP 입니다 ({e['repo']}@{e['commit'][:10]}).

## 쓰는 법 (온라인 — 사내 승인 저장소에서 받음)

쓰는 MCP 클라이언트의 설정 파일에 configs/ 의 해당 파일 내용을 넣습니다.

| 클라이언트 | 파일 |
|---|---|
| Claude Code | configs/claude-code.mcp.json → 프로젝트 .mcp.json |
| Claude Desktop | configs/claude_desktop_config.json |
| Cursor | configs/cursor.mcp.json → .cursor/mcp.json |
| VS Code | configs/vscode.mcp.json → .vscode/mcp.json |
| goose | configs/goose.yaml → config.yaml 의 extensions |

PC 준비물: uv (uvx 명령).

## 오프라인 설치

wheels/ 에 검사 때 고정한 휠이 모두 있습니다(해시 = kit-lock.json).

```
uvx --offline --no-index --find-links wheels --from {e['package']}=={e['version']} {e['entry']}
```
"""
    return _zip(files)


def build_all(name, e, server, out_dir, approved_dir, norm):
    out = Path(out_dir) / name
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        old.unlink()
    made = {}
    for kind, data in (("mcpb", build_mcpb(name, e, server)), ("zip", build_zip(name, e, server, approved_dir, norm))):
        f = out / f"{name}-{e['version']}.{kind}"
        f.write_bytes(data)
        made[kind] = {"file": f.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return made
