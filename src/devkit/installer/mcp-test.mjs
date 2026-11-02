#!/usr/bin/env node
// MCP Dev Kit — mcp-test (리눅스·윈도우 같은 코드)
// 실행할 때마다 사내 서버에서 개발자 PC 정책을 받고, srt 샌드박스 안에서 goose 를 띄운다.
//  · 바깥 접속 = 정책의 허용 도메인 + 사내 서버만 (srt 네트워크 허용목록)
//  · 파일 = 지금 작업 폴더 밖 홈 디렉터리는 읽기·쓰기 모두 막음 (goose 자기 설정 폴더만 예외)
//  · 정책을 못 받으면 실행하지 않는다 (fail-closed)
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";

const WIN = process.platform === "win32";
const HOME = homedir();
const CONF = WIN ? join(process.env.LOCALAPPDATA, "mcp-dev-kit") : join(HOME, ".config", "mcp-dev-kit");
const kit = JSON.parse(readFileSync(join(CONF, "kit.json"), "utf8"));   // {public, goose, srt_cli}
const token = readFileSync(join(CONF, "token"), "utf8").trim();
const args = process.argv.slice(2);
const mode = args[0] === "run" ? "run" : "session";
const gooseArgs = args.length ? args : ["session"];
const say = m => process.stderr.write(`mcp-test: ${m}\n`);

let policy;
try {
  const r = await fetch(`${kit.public}/api/devkit/policy?mode=${mode}`, {headers: {Authorization: `Bearer ${token}`, "User-Agent": `mcp-test/${process.platform}`}});
  if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
  policy = await r.json();
} catch (e) {
  say(`사내 서버에서 정책을 받지 못해 실행하지 않습니다 — ${e.message}`);
  process.exit(3);
}

const env = {...process.env, GOOSE_PROVIDER: "openai", GOOSE_MODEL: "kit-llm", OPENAI_HOST: `${kit.public}/llm`, OPENAI_API_KEY: token,
  GOOSE_TELEMETRY_OFF: "1", GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: process.env.MCP_TEST_MODE || policy.goose_mode[mode]};
if (kit.ca_bundle && existsSync(kit.ca_bundle)) env.SSL_CERT_FILE = kit.ca_bundle;

const work = process.cwd();
const gooseDirs = WIN
  ? [join(process.env.APPDATA, "Block", "goose"), join(process.env.LOCALAPPDATA, "Block", "goose")]
  : [".config/goose", ".local/share/goose", ".local/state/goose", ".cache/goose"].map(d => join(HOME, d));
for (const d of gooseDirs) mkdirSync(d, {recursive: true});
// srt 는 샌드박스 안 TMPDIR 을 /tmp/claude 로 두고 그 폴더를 묶어 넣는다 — 없으면 goose 가 임시 파일을 못 만든다
if (!WIN) mkdirSync("/tmp/claude", {recursive: true});

say(`정책 v${policy.version} · 샌드박스 ${policy.sandbox === "required" ? (policy.linux_container_mode && !WIN ? "srt(컨테이너 약한 모드)" : "srt") : "끔"} · 바깥 허용 ${policy.network_allowed.join(", ")} · 작업 폴더 ${work} · 툴 호출 ${env.GOOSE_MODE}`);

if (policy.sandbox !== "required") {
  spawn(kit.goose, gooseArgs, {stdio: "inherit", env}).on("exit", c => process.exit(c ?? 1));
} else {
  // srt 프록시는 허용 도메인이라도 사내 IP 로 풀리면 막는다 — 키트 서버 주소가 풀리는 IP:포트를 같이 허용한다
  const pub = new URL(kit.public);
  const kitAddrs = (await lookup(pub.hostname, {all: true, family: 4}).catch(() => [])).map(a => `${a.address}:${pub.port || 443}`);
  const settings = {
    network: {allowedDomains: [...policy.network_allowed, ...kitAddrs], deniedDomains: []},
    filesystem: {
      denyRead: policy.workspace_only ? [HOME] : [],
      allowRead: [work, kit.dir, CONF, ...gooseDirs],
      allowWrite: [work, ...gooseDirs, tmpdir()],
      denyWrite: [join(CONF, "token"), join(CONF, "kit.json")],
    },
  };
  // 관리자가 켠 컨테이너 개발환경 모드 (리눅스만): 도커 안 bubblewrap 용 srt 약한 모드 — 유닉스 소켓 차단이 빠진다
  if (policy.linux_container_mode && !WIN) { settings.enableWeakerNestedSandbox = true; settings.network.allowAllUnixSockets = true; }
  const file = join(CONF, "srt-settings.json");
  writeFileSync(file, JSON.stringify(settings, null, 2));
  // srt CLI 는 인자를 bash 식 작은따옴표로 묶는데 윈도우에서는 cmd.exe 가 실행한다 — 윈도우는 cmd 식으로 묶어 -c 로 넘긴다
  const winQuote = a => /^[\w.:\\\/=-]+$/.test(a) ? a : `"${a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
  // 윈도우 srt 는 샌드박스 명령에 PATH·프록시 변수만 넘긴다 — goose 설정은 안쪽 cmd 가 직접 넣고, 개인 키는 명령줄에 드러나지 않게 파일에서 읽는다
  const gooseEnv = ["GOOSE_PROVIDER", "GOOSE_MODEL", "OPENAI_HOST", "GOOSE_TELEMETRY_OFF", "GOOSE_DISABLE_KEYRING", "GOOSE_MODE", "SSL_CERT_FILE"]
    .filter(k => env[k]).map(k => `set "${k}=${env[k]}"&& `).join("");
  const cmd = WIN
    // 샌드박스 사용자도 PC 공통 NO_PROXY 를 물려받는다 — 그대로 두면 사내 서버로 직접 붙다 WFP 에 막히므로 비운다
    ? ["-c", `set "NO_PROXY="&& set "no_proxy="&& ${gooseEnv}set /p OPENAI_API_KEY=<"${join(CONF, "token")}"&& ` + [kit.goose, ...gooseArgs].map(winQuote).join(" ")]
    : [kit.goose, ...gooseArgs];
  spawn(process.execPath, [kit.srt_cli, "--settings", file, ...cmd], {stdio: "inherit", env})
    .on("exit", c => process.exit(c ?? 1));
}
