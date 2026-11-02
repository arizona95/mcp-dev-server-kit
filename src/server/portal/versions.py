"""버전 관리 화면 API — 배포 묶음 목록 · 올리기 · 설치 · 진행 상태 · 적용 중 잠금.

목록·설치는 root 업데이트 에이전트(/run/kit-update.sock)가 한다(서명 확인 · 이미지 불러오기 · 업데이트 담당 컨테이너).
적용 중에는 /data/update/maintenance 표지가 있고, 그동안 포털은 화면 보기(GET)만 받고 바꾸는 요청은 모두 503 으로 막는다.
"""
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from fastapi import Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

DATA = Path(os.environ.get("KIT_DATA", "/data"))
STATUS, FLAG = DATA / "update" / "status.json", DATA / "update" / "maintenance"
UPLOADS = DATA / "releases"
STATIC = Path(__file__).parent / "static"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "kit-cli"))


def agent(obj):
    import update_agent
    try:
        return update_agent.request(obj)
    except OSError as e:
        raise HTTPException(502, f"업데이트 에이전트에 닿지 않습니다: {e}")


def register(app, h):
    @app.middleware("http")
    async def maintenance(request: Request, call_next):
        """적용 중에는 화면 보기만 — 바꾸는 요청(POST·PUT·DELETE)은 막는다. 진행 상태 조회·LLM 은 그대로."""
        if FLAG.exists() and request.method not in ("GET", "HEAD") and not request.url.path.startswith(("/api/update/", "/_auth/")):
            return JSONResponse({"detail": "버전 업데이트 중이라 지금은 바꿀 수 없습니다. 끝나면 다시 해 주세요."}, status_code=503)
        return await call_next(request)

    @app.get("/api/update/status")
    def update_status(_=Depends(h.user)):
        s = json.loads(STATUS.read_text()) if STATUS.exists() else {"state": "idle"}
        s["locked"] = FLAG.exists()
        return s

    @app.get("/api/versions")
    def versions(_=Depends(h.superadmin)):
        r = agent({"cmd": "list"})
        if not r.get("ok"):
            raise HTTPException(502, r.get("error", "목록 실패"))
        return {"current": r["current"], "releases": r["releases"], "status": update_status(None)}

    @app.post("/api/versions/install")
    async def install(request: Request, who=Depends(h.superadmin)):
        body = await request.json()
        v = str(body.get("version", ""))
        if not re.fullmatch(r"\d+\.\d+\.\d+", v):
            raise HTTPException(400, "버전 형식이 아닙니다")
        r = agent({"cmd": "install", "version": v, "who": who})
        if not r.get("ok"):
            raise HTTPException(409, r.get("error", "설치 실패"))
        return r

    @app.post("/api/versions/upload")
    async def upload(file: UploadFile = File(...), who=Depends(h.superadmin)):
        """배포 묶음 폴더를 묶은 .tar 를 올린다 — /data/releases/<폴더> 로 푼다(서명은 목록에서 확인)."""
        UPLOADS.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=UPLOADS, delete=False, suffix=".part") as tmp:
            while chunk := await file.read(8 << 20):
                tmp.write(chunk)
        try:
            with tarfile.open(tmp.name) as t:
                names = t.getnames()
                tops = {n.split("/")[0] for n in names}
                if len(tops) != 1 or not re.fullmatch(r"mcp-dev-server-kit-v\d+\.\d+\.\d+", next(iter(tops))):
                    raise HTTPException(400, "묶음 폴더 하나(mcp-dev-server-kit-v<버전>/)를 tar 로 묶어 올려 주세요")
                for m in t.getmembers():
                    if m.issym() or m.islnk() or ".." in Path(m.name).parts or m.name.startswith("/"):
                        raise HTTPException(400, f"허용하지 않는 항목: {m.name}")
                top = next(iter(tops))
                shutil.rmtree(UPLOADS / top, ignore_errors=True)
                t.extractall(UPLOADS)
        finally:
            os.unlink(tmp.name)
        h.event("release_upload", who, folder=top)
        return {"ok": True, "folder": top}

    @app.get("/admin/versions")
    def versions_page(_=Depends(h.superadmin)):
        return FileResponse(STATIC / "versions.html")
