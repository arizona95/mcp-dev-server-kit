#!/usr/bin/env node
// MCP Dev Kit — mcp-test (리눅스·윈도우 같은 코드)
// 실행할 때마다 ① 브라우저 로그인으로 실행 토큰을 받고(PC 에 저장하지 않음 — 이 프로세스 메모리에만, P7)
// ② 사내 서버에서 개발자 PC 정책을 받아(못 받으면 실행 안 함) ③ srt 샌드박스 안에서 goose 를 띄운다.
//  · 바깥 접속 = 정책의 허용 도메인 + 사내 서버만 (srt 네트워크 허용목록)
//  · 파일 = 지금 작업 폴더 밖 홈 디렉터리는 읽기·쓰기 모두 막음
//  · 사람 승인(P4) = 정책이 강제하면 대화형은 매번 묻기, run 은 툴 호출 없는 chat — goose 설정은 실행마다 새 폴더(항상 허용이 남지 않음)
//  · MCP 비밀값(P21) = kit-mcp.json 의 "secrets" 이름을 키 저장소 → PC 의 OS 암호화 저장소 → PC 환경 변수 순으로(정책이 허용한 출처만) 찾아
//    샌드박스 안 goose(와 그 MCP)의 환경 변수로만 넘긴다. 디스크·명령줄에 쓰지 않는다.
import { readFileSync, writeFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { spawn, execFileSync } from "node:child_process";
import { lookup } from "node:dns/promises";
import { createServer as httpServer } from "node:http";
import { createServer as netServer } from "node:net";
import { randomBytes } from "node:crypto";

const WIN = process.platform === "win32";
const WIN_PORTS = [60080, 60143];
const HOME = homedir();
const CONF = WIN ? join(process.env.LOCALAPPDATA, "mcp-dev-kit") : join(HOME, ".config", "mcp-dev-kit");
const kit = JSON.parse(readFileSync(join(CONF, "kit.json"), "utf8"));   // {public, dir, goose, srt_cli, ca_bundle}
const args = process.argv.slice(2);
const mode = args[0] === "run" ? "run" : "session";
const gooseArgs = args.length ? args : ["session"];
const say = m => process.stderr.write(`mcp-test: ${m}\n`);
const rand = () => randomBytes(12).toString("hex");

// ① 실행 토큰 — 브라우저(사내 로그인)로 받아 127.0.0.1 로 돌려받는다
async function login() {
  const state = rand();
  return await new Promise((resolve, reject) => {
    const srv = httpServer((req, res) => {
      const u = new URL(req.url, "http://127.0.0.1");
      if (u.pathname !== "/cb" || u.searchParams.get("state") !== state) { res.writeHead(404).end(); return; }
      res.writeHead(200, {"Content-Type": "text/html; charset=utf-8"})
        .end("<!doctype html><meta charset=utf-8><title>MCP Dev Kit</title><p style='font:16px sans-serif;margin:40px'>mcp-test 로그인 완료 — 이 창을 닫아도 됩니다.</p>");
      srv.close();
      resolve(u.searchParams.get("token"));
    });
    srv.listen(0, "127.0.0.1", () => {
      const url = `${kit.public}/cli/login?port=${srv.address().port}&state=${state}`;
      say(`브라우저에서 사내 로그인 — 열리지 않으면 이 주소를 여세요: ${url}`);
      if (process.env.KIT_LOGIN_OPEN === "print") return;   // 자동 시험용: 주소만 출력
      try {
        if (WIN) spawn("rundll32", ["url.dll,FileProtocolHandler", url], {detached: true, stdio: "ignore"}).unref();
        else spawn("xdg-open", [url], {detached: true, stdio: "ignore"}).on("error", () => {}).unref();
      } catch {}
    });
    setTimeout(() => { srv.close(); reject(new Error("3분 안에 로그인하지 않았습니다")); }, 180000);
  });
}

let token, policy;
try {
  token = await login();
  const r = await fetch(`${kit.public}/api/devkit/policy?mode=${mode}`, {headers: {Authorization: `Bearer ${token}`, "User-Agent": `mcp-test/${process.platform}`}});
  if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
  policy = await r.json();
} catch (e) {
  say(`사내 서버에서 정책을 받지 못해 실행하지 않습니다 — ${e.message}`);
  process.exit(3);
}

// ② 사람 승인(P4) — 정책이 강제하면 개발자가 바꿀 수 없다
let gooseMode = policy.goose_mode[mode];
if (policy.hitl_required) gooseMode = mode === "session" ? "approve" : "chat";

// ③ MCP 비밀값(P21)
const work = process.cwd();
// "secrets": ["SLACK_TOKEN", {"env": "GITHUB_TOKEN", "name": "GH_TOKEN"}] — env = MCP 가 받는 환경 변수, name = 저장소에 넣은 이름
// (사내 Git 은 GITHUB_·GITEA_ 로 시작하는 비밀값 이름을 막는다 — 그럴 때 다른 이름으로 넣고 env 로 이어 준다)
const okName = n => typeof n === "string" && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(n);
let decl = [];
try { decl = (JSON.parse(readFileSync(join(work, "kit-mcp.json"), "utf8")).secrets || []).map(x => typeof x === "string" ? {env: x, name: x} : x).filter(x => okName(x.env) && okName(x.name)); } catch {}
const wanted = decl.map(x => x.name), envOf = Object.fromEntries(decl.map(x => [x.name, x.env]));
const sources = policy.secret_sources || ["kms", "keyring", "env"];
const secrets = {}, from = {};
if (wanted.length && sources.includes("kms")) {
  let repo = "";
  try { repo = execFileSync("git", ["-C", work, "remote", "get-url", "origin"], {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]}).trim().replace(/\.git$/, "").split("/git/")[1] || ""; } catch {}
  const r = await fetch(`${kit.public}/api/devkit/secrets`, {method: "POST", headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"}, body: JSON.stringify({names: wanted, repo})});
  if (r.ok) for (const [k, v] of Object.entries((await r.json()).values)) { secrets[k] = v; from[k] = "키 저장소"; }
}
function keyring(name) {   // PC 의 OS 암호화 저장소 — 윈도우 자격 증명 관리자(일반 자격 증명 'mcp-dev-kit:<이름>') · 리눅스 keyring(secret-tool)
  try {
    if (WIN) {
      const ps = `$t='mcp-dev-kit:${name}';Add-Type -Namespace K -Name C -MemberDefinition '[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern bool CredRead(string t,int ty,int f,out IntPtr c);[DllImport("advapi32.dll")]public static extern void CredFree(IntPtr c);';$p=[IntPtr]::Zero;if([K.C]::CredRead($t,1,0,[ref]$p)){$n=[Runtime.InteropServices.Marshal]::ReadInt32($p,32);$b=[Runtime.InteropServices.Marshal]::ReadIntPtr($p,40);[Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringUni($b,$n/2));[K.C]::CredFree($p)}`;
      return execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps], {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]}).trim();
    }
    return execFileSync("secret-tool", ["lookup", "service", "mcp-dev-kit", "name", name], {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]}).trim();
  } catch { return ""; }
}
for (const n of wanted.filter(n => !(n in secrets))) {
  const v = sources.includes("keyring") ? keyring(n) : "";
  if (v) { secrets[n] = v; from[n] = "PC 암호화 저장소"; }
  else if (sources.includes("env") && (process.env[envOf[n]] || process.env[n])) { secrets[n] = process.env[envOf[n]] || process.env[n]; from[n] = "PC 환경 변수"; }
}
const missing = wanted.filter(n => !(n in secrets));

const env = {...process.env, GOOSE_PROVIDER: "openai", GOOSE_MODEL: "kit-llm", OPENAI_HOST: `${kit.public}/llm`,
  GOOSE_TELEMETRY_OFF: "1", GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: gooseMode};
delete env.OPENAI_API_KEY;
if (kit.ca_bundle && existsSync(kit.ca_bundle)) env.SSL_CERT_FILE = kit.ca_bundle;
// goose 설정은 실행마다 빈 폴더 — '항상 허용'·세션 기록이 다음 실행으로 넘어가지 않는다
const runRoot = WIN ? "" : mkdtempSync(join(tmpdir(), "kit-goose-"));
if (!WIN) env.GOOSE_PATH_ROOT = runRoot;
// srt 는 샌드박스 안 TMPDIR 을 /tmp/claude 로 두고 그 폴더를 묶어 넣는다 — 없으면 goose 가 임시 파일을 못 만든다
if (!WIN) mkdirSync("/tmp/claude", {recursive: true});

say(`정책 v${policy.version} · 샌드박스 ${policy.sandbox === "required" ? (policy.linux_container_mode && !WIN ? "srt(컨테이너 약한 모드)" : "srt") : "끔"} · 바깥 허용 ${policy.network_allowed.join(", ")} · 작업 폴더 ${work} · 툴 호출 ${gooseMode}${policy.hitl_required ? "(정책 강제)" : ""}`);
if (wanted.length) say(`MCP 비밀값: ${wanted.map(n => `${envOf[n] !== n ? `${envOf[n]}←${n}` : n}(${n in secrets ? from[n] : "없음"})`).join(", ")}`);
if (missing.length) say(`없는 비밀값 ${missing.join(", ")} — 사내 Git 설정 > Actions > Secrets 에 넣어 주세요: ${kit.public}/git/user/settings/actions/secrets`);

const report = (event, extra = {}) => fetch(`${kit.public}/api/devkit/run`, {method: "POST", headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
  body: JSON.stringify({event, mode, os: process.platform, secrets: Object.keys(secrets), ...extra})}).catch(() => {});
await report("start");
const done = c => { if (runRoot) rmSync(runRoot, {recursive: true, force: true}); report("end", {code: c}).finally(() => process.exit(c ?? 1)); };

const values = {OPENAI_API_KEY: token, ...Object.fromEntries(Object.entries(secrets).map(([n, v]) => [envOf[n] || n, v]))};
if (policy.sandbox !== "required") {
  spawn(kit.goose, gooseArgs, {stdio: "inherit", env: {...env, ...values}}).on("exit", done);
} else {
  // srt 프록시는 허용 도메인이라도 사내 IP 로 풀리면 막는다 — 키트 서버 주소가 풀리는 IP:포트를 같이 허용한다
  const pub = new URL(kit.public);
  const kitAddrs = (await lookup(pub.hostname, {all: true, family: 4}).catch(() => [])).map(a => `${a.address}:${pub.port || 443}`);
  const settings = {
    network: {allowedDomains: [...policy.network_allowed, ...kitAddrs], deniedDomains: []},
    filesystem: {
      denyRead: policy.workspace_only ? [HOME] : [],
      allowRead: [work, kit.dir, CONF, ...(runRoot ? [runRoot] : [])],
      allowWrite: [work, tmpdir()],
      denyWrite: [join(CONF, "kit.json")],
    },
  };
  // 윈도우: srt 프록시·루프백 허용 포트 범위 — windows-install --proxy-port-range 와 같아야 한다(폭 ≤ 64)
  if (WIN) settings.windows = {proxyPortRange: WIN_PORTS};
  // 관리자가 켠 컨테이너 개발환경 모드 (리눅스만): 도커 안 bubblewrap 용 srt 약한 모드 — 유닉스 소켓 차단이 빠진다
  if (policy.linux_container_mode && !WIN) { settings.enableWeakerNestedSandbox = true; settings.network.allowAllUnixSockets = true; }
  const file = join(CONF, "srt-settings.json");
  writeFileSync(file, JSON.stringify(settings, null, 2));
  if (!WIN) {
    spawn(process.execPath, [kit.srt_cli, "--settings", file, kit.goose, ...gooseArgs], {stdio: "inherit", env: {...env, ...values}}).on("exit", done);
  } else {
    // 윈도우 srt 는 샌드박스 명령에 PATH·프록시 변수만 넘긴다(명령은 cmd.exe 가 실행). 일반 설정은 안쪽 cmd 가 set 으로 넣고,
    // 토큰·비밀값은 명령줄·파일에 드러나지 않게 한 번만 읽히는 네임드 파이프로 넘긴다(set /p NAME=<\\.\pipe\…).
    const pipes = [];
    const pipeSet = Object.entries(values).map(([k, v]) => {
      const path = `\\\\.\\pipe\\kit-${rand()}`;
      const s = netServer(sock => { sock.end(v + "\r\n"); s.close(); }).listen(path);
      pipes.push(s);
      return `set /p ${k}=<"${path}"&& `;
    }).join("");
    const winQuote = a => /^[\w.:\\\/=-]+$/.test(a) ? a : `"${a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
    const gooseEnv = ["GOOSE_PROVIDER", "GOOSE_MODEL", "OPENAI_HOST", "GOOSE_TELEMETRY_OFF", "GOOSE_DISABLE_KEYRING", "GOOSE_MODE", "SSL_CERT_FILE"]
      .filter(k => env[k]).map(k => `set "${k}=${env[k]}"&& `).join("");
    const root = `%TEMP%\\kit-goose-${rand()}`;
    // 샌드박스 사용자도 PC 공통 NO_PROXY 를 물려받는다 — 그대로 두면 사내 서버로 직접 붙다 WFP 에 막히므로 비운다
    // 파이썬 보정(pyshim/sitecustomize.py): 루프백 socketpair 를 허용 범위 안에서 만든다 — 없으면 asyncio MCP 가 시작하다 멈춘다
    const line = `chcp 65001>nul&& set "NO_PROXY="&& set "no_proxy="&& set "PYTHONPATH=${join(kit.dir, "pyshim")}"&& set "KIT_LOOPBACK_RANGE=${WIN_PORTS.join("-")}"&& `
      + `mkdir "${root}"&& set "GOOSE_PATH_ROOT=${root}"&& ${gooseEnv}${pipeSet}` + [kit.goose, ...gooseArgs].map(winQuote).join(" ") + ` & rmdir /s /q "${root}"`;
    spawn(process.execPath, [kit.srt_cli, "--settings", file, "-c", line], {stdio: "inherit", env})
      .on("exit", c => { pipes.forEach(p => p.close()); done(c); });
  }
}
