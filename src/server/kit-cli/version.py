"""키트 버전표 — 이 이미지에 실제로 들어 있는 구성요소 버전(설치된 것을 직접 읽는다 · 손으로 적지 않음).

  kit version          표로
  kit version --json   배포 묶음 manifest.json 에 넣는 모양
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BUILD = Path("/opt/kit/BUILD.json")


def _out(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def _pkg(venv, name):
    for d in Path(venv).glob(f"lib/python*/site-packages/{name.replace('-', '_')}-*.dist-info"):
        return d.name.removesuffix(".dist-info").split("-", 1)[1]
    return ""


def components():
    goose = (Path("/opt/kit/devkit/hosts/goose/VERSION").read_text() if Path("/opt/kit/devkit/hosts/goose/VERSION").exists() else "")
    srt = ""
    try:
        import tarfile
        with tarfile.open("/opt/kit/devkit/hosts/srt/srt-bundle.tgz") as t:
            m = t.extractfile("srt-bundle/node_modules/@anthropic-ai/sandbox-runtime/package.json")
            srt = json.load(m)["version"]
    except Exception:
        pass
    ss = ""
    pp = Path("/opt/kit/vendor/skillspector/pyproject.toml")
    if pp.exists():
        m = re.search(r'^version\s*=\s*"([^"]+)"', pp.read_text(), re.M)
        ss = m.group(1) if m else ""
    return [
        ("Gitea (사내 Git)", re.sub(r"(?is)^gitea version (\S+).*", r"\1", _out(["/opt/kit/bin/gitea", "--version"]))),
        ("LiteLLM (LLM 게이트웨이)", _pkg("/opt/kit/litellm-venv", "litellm")),
        ("goose (개발자 PC 호스트)", next((l.split("=", 1)[1] for l in goose.splitlines() if l.startswith("version=")), "")),
        ("srt (sandbox-runtime)", srt),
        ("SkillSpector (감시자)", ss),
        ("FastAPI (포털)", _pkg("/opt/kit/venv", "fastapi")),
        ("uv", _pkg("/opt/kit/venv", "uv")),
        ("Squid (바깥 접속 프록시)", re.sub(r".*Version (\S+).*", r"\1", _out(["squid", "-v"]).splitlines()[0] if _out(["squid", "-v"]) else "")),
        ("nginx", re.sub(r".*nginx/(\S+).*", r"\1", subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr.strip())),
        ("docker CLI", _out(["docker", "--version"]).replace("Docker version ", "").split(",")[0]),
        ("Python", sys.version.split()[0]),
    ]


def info():
    b = json.loads(BUILD.read_text()) if BUILD.exists() else {}
    return {"version": os.environ.get("KIT_VERSION", b.get("version", "dev")), "built": b.get("built", ""), "commit": b.get("commit", ""),
            "base_image": b.get("base_image", ""), "apt_snapshot": b.get("apt_snapshot", ""),
            "components": [{"name": n, "version": v} for n, v in components()]}


def main():
    i = info()
    if "--json" in sys.argv:
        print(json.dumps(i, ensure_ascii=False, indent=1))
        return
    print(f"MCP Dev Kit v{i['version']}  (빌드 {i['built'] or '-'}  커밋 {i['commit'][:10] or '-'})")
    print(f"  기반 이미지 {i['base_image'] or '-'}  ·  apt 스냅숏 {i['apt_snapshot'] or '-'}")
    w = max(len(c["name"]) for c in i["components"])
    for c in i["components"]:
        print(f"  {c['name']:<{w}}  {c['version'] or '-'}")


if __name__ == "__main__":
    main()
