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
  const settings = {
    network: {allowedDomains: policy.network_allowed, deniedDomains: []},
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
  spawn(process.execPath, [kit.srt_cli, "--settings", file, kit.goose, ...gooseArgs], {stdio: "inherit", env})
    .on("exit", c => process.exit(c ?? 1));
}
