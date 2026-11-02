#!/usr/bin/env node
// MCP Dev Kit — mcp-gate: 샌드박스 안에서 개발 중인 MCP 앞에 서는 관문 (P4 사람 승인)
//   goose ⇄ (stdio) ⇄ mcp-gate ⇄ (stdio) ⇄ 개발 중인 MCP          (모두 srt 샌드박스 안)
//   tools/call 이 오면 샌드박스 밖 mcp-test 에 루프백 포트로 묻고, 사람이 허용해야 MCP 에 넘긴다.
//   거부하면 MCP 를 부르지 않고 '거부됨' 결과를 goose 에 돌려준다. goose 설정과 무관하게 늘 이 관문을 지난다.
// 사용(mcp-test 가 붙인다): node mcp-gate.mjs <승인 포트> <base64url(MCP 실행 명령)>
import { spawn } from "node:child_process";
import { connect } from "node:net";
import { createInterface } from "node:readline";

const [port, b64] = process.argv.slice(2);
const command = Buffer.from(b64, "base64url").toString("utf8");
const child = spawn(command, {shell: true, stdio: ["pipe", "pipe", "inherit"]});
child.on("exit", c => process.exit(c ?? 0));

function ask(call) {
  return new Promise(resolve => {
    const s = connect(Number(port), "127.0.0.1");
    let buf = "";
    s.on("connect", () => s.write(JSON.stringify(call) + "\n"));
    s.on("data", d => { buf += d; if (buf.includes("\n")) { s.end(); try { resolve(JSON.parse(buf).allow === true); } catch { resolve(false); } } });
    s.on("error", () => resolve(false));   // 물을 곳이 없으면 거부(fail-closed)
  });
}

createInterface({input: process.stdin}).on("line", async line => {
  let msg;
  try { msg = JSON.parse(line); } catch { child.stdin.write(line + "\n"); return; }
  if (msg.method === "tools/call") {
    const ok = await ask({tool: msg.params?.name, args: msg.params?.arguments ?? {}});
    if (!ok) {
      process.stdout.write(JSON.stringify({jsonrpc: "2.0", id: msg.id,
        result: {content: [{type: "text", text: "사용자가 이 툴 호출을 승인하지 않았습니다 (MCP 를 부르지 않음)"}], isError: true}}) + "\n");
      return;
    }
  }
  child.stdin.write(line + "\n");
}).on("close", () => child.stdin.end());
child.stdout.pipe(process.stdout);
