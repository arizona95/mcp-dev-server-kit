// 공통 머리줄: 역할(주관리자 / 관리자 / 개발자)에 맞춰 메뉴를 그린다. <nav class="nav" id="nav" data-on="/mcp"></nav>
(async () => {
  const nav = document.getElementById("nav"); if (!nav) return;
  const me = await fetch("/api/me").then(r => r.ok ? r.json() : null).catch(() => null);
  const items = [["/new", "신규 개발"], ["/mcp", "MCP 등록"], ["/download", "다운로드"], ["/git/", "Git"]];
  if (me && me.is_admin) items.push(["/admin/registry", "레지스트리"], ["/admin/monitor", "모니터링"], ["/admin/egress", "서버 외부 접속"], ["/admin/devpolicy", "개발자 PC 정책"]);
  if (me && me.is_super) items.push(["/admin/users", "계정·접근"]);
  const on = nav.dataset.on;
  nav.innerHTML = items.map(([h, t]) => `<a href="${h}"${h === on ? ' class="on"' : ""}>${t}</a>`).join("");
  if (me) document.querySelector(".top").insertAdjacentHTML("beforeend",
    `<span class="dim" style="margin-left:auto">${me.login} · <b>${me.role_label}</b> · <a href="/logout" class="dim">로그아웃</a></span>`);
  window.KIT_ME = me;
  document.dispatchEvent(new CustomEvent("kit-me", {detail: me}));
})();
