// 공통 머리줄: 역할(주관리자 / 관리자 / 개발자)에 맞춰 메뉴를 그린다. <nav class="nav" id="nav" data-on="/mcp"></nav>
(async () => {
  const nav = document.getElementById("nav"); if (!nav) return;
  const me = await fetch("/api/me").then(r => r.ok ? r.json() : null).catch(() => null);
  const items = [["/new", "신규 개발"], ["/mcp", "MCP 등록"], ["/download", "다운로드"], ["/git/", "Git"]];
  if (me && me.is_admin) items.push(["/admin/assets", "자산 현황"], ["/admin/registry", "레지스트리"], ["/admin/watchers", "감시자"], ["/admin/dlp", "LLM 차단 패턴"], ["/admin/monitor", "모니터링"], ["/admin/egress", "서버 외부 접속"], ["/admin/devpolicy", "개발자 PC 정책"]);
  if (me && me.is_super) items.push(["/admin/users", "계정·접근"], ["/admin/versions", "버전 관리"]);
  const on = nav.dataset.on;
  nav.innerHTML = items.map(([h, t]) => `<a href="${h}"${h === on ? ' class="on"' : ""}>${t}</a>`).join("");
  if (me) document.querySelector(".top").insertAdjacentHTML("beforeend",
    `<span class="dim" style="margin-left:auto">${me.login} · <b>${me.role_label}</b> · <a href="/logout" class="dim">로그아웃</a></span>`);
  window.KIT_ME = me;
  document.dispatchEvent(new CustomEvent("kit-me", {detail: me}));
})();

// 버전 업데이트 중이면 모든 화면을 잠그고 진행률을 보여 준다(정리 → 패치 적용 검사 → 백업 → 적용 → 점검 / 실패 시 롤백).
// 진행 중에만 상태를 다시 읽는다. 컨테이너를 바꾸는 순간에는 서버가 잠깐 끊긴다 — 다시 붙을 때까지 기다린다.
(() => {
  const ICON = {wait: "○", running: "◐", done: "●", failed: "✕"};
  let timer = null, lastOk = null;
  function box() {
    let o = document.getElementById("kit-update");
    if (!o) {
      o = document.createElement("div"); o.id = "kit-update";
      o.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(248,249,251,.97);display:flex;align-items:center;justify-content:center";
      o.innerHTML = '<div style="width:min(640px,92vw);background:#fff;border:1px solid #dde2ea;border-radius:14px;padding:28px 30px;box-shadow:0 8px 30px rgba(0,0,0,.08)">' +
        '<div id="ku-title" style="font-size:20px;font-weight:700;margin-bottom:6px"></div><div id="ku-sub" style="color:#667;font-size:13px;margin-bottom:14px"></div>' +
        '<div style="height:10px;background:#eef1f5;border-radius:6px;overflow:hidden"><div id="ku-bar" style="height:100%;width:0;background:#1f5fd6;transition:width .4s"></div></div>' +
        '<div id="ku-steps" style="margin:16px 0;font-size:14px;line-height:1.9"></div><div id="ku-msg" style="font-size:13px"></div></div>';
      document.body.appendChild(o);
    }
    return o;
  }
  function paint(s, offline) {
    const o = box(), run = ["running", "rolling_back"].includes(s.state);
    document.getElementById("ku-title").textContent = offline ? "서버를 바꾸는 중 — 다시 연결하는 중…" :
      ({running: "버전 업데이트 중", rolling_back: "실패 — 지금 버전으로 되돌리는 중", done: "업데이트 완료", rolled_back: "적용하지 못해 되돌렸습니다", failed: "업데이트 실패"}[s.state] || "버전 업데이트");
    document.getElementById("ku-sub").textContent = `v${s.from || "?"} → v${s.to || "?"} · 진행 중에는 아무것도 누를 수 없습니다`;
    document.getElementById("ku-bar").style.width = `${s.pct || 0}%`;
    document.getElementById("ku-bar").style.background = s.state === "done" ? "#1d9a5b" : (["rolled_back", "failed", "rolling_back"].includes(s.state) ? "#c0392b" : "#1f5fd6");
    document.getElementById("ku-steps").innerHTML = (s.steps || []).map(x => `<div>${ICON[x.state] || "○"} <b>${x.name}</b> <span style="color:#667">${(x.detail || "").replace(/[<>&]/g, "")}</span></div>`).join("");
    document.getElementById("ku-msg").innerHTML = run || offline ? "" : `${(s.message || "").replace(/[<>&]/g, "")} <button class="btn sm" onclick="location.reload()">확인</button>`;
  }
  async function tick() {
    let s;
    try { const r = await fetch("/api/update/status", {cache: "no-store"}); if (!r.ok) throw 0; s = await r.json(); lastOk = s; }
    catch { if (lastOk) paint(lastOk, true); timer = setTimeout(tick, 3000); return; }
    const run = ["running", "rolling_back"].includes(s.state) || s.locked;
    if (run || (lastOk && timer)) paint(s, false);
    if (run) timer = setTimeout(tick, 2000);
    else timer = null;
  }
  window.KIT_UPDATE_WATCH = () => { timer = timer || 1; tick(); };
  document.addEventListener("kit-me", ev => { if (ev.detail) tick(); });
})();
