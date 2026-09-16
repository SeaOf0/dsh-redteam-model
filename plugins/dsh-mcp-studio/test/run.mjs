// mcp-studio 测试：SSE 桥接端到端（本地 mock SSE 服务器，覆盖 LF 与 CRLF 两种帧行尾）。
import { spawn } from "node:child_process";
import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert";

const BRIDGE = fileURLToPath(new URL("../lib/sse-bridge.mjs", import.meta.url));
let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) { pass++; console.log(`ok   ${label}`); } else { fail++; console.log(`FAIL ${label}`); } };

function startMockSse(lineEnding) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(`event: endpoint${lineEnding}data: http://127.0.0.1:${server.address().port}/message?sessionId=t1${lineEnding}${lineEnding}`);
        server._respond = (payload) => res.write(`data: ${JSON.stringify(payload)}${lineEnding}${lineEnding}`);
      } else if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          res.writeHead(202);
          res.end();
          const message = JSON.parse(body);
          if (message.id !== undefined) {
            server._respond({ jsonrpc: "2.0", id: message.id, result: { echo: message.method } });
          }
        });
      }
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

async function bridgeSession(port) {
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BRIDGE, `http://127.0.0.1:${port}/sse`, "{}"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error("bridge session timeout")); }, 8000);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      out += chunk;
      for (const line of out.split("\n")) {
        if (line.trim() === "") continue;
        try {
          const message = JSON.parse(line);
          if (message.id === 2) { clearTimeout(timer); child.kill(); resolve(message); return; }
        } catch { /* 行未完整 */ }
      }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => console.error("  [bridge stderr]", chunk.trim()));
    const send = (payload) => child.stdin.write(JSON.stringify(payload) + "\n");
    setTimeout(() => send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } }), 300);
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), 600);
  });
}

for (const [label, ending] of [["LF 帧", "\n"], ["CRLF 帧（yak 形态）", "\r\n"]]) {
  const server = await startMockSse(ending);
  try {
    const reply = await bridgeSession(server.address().port);
    ok(`${label}：initialize+tools/list 经桥接往返`, reply?.result?.echo === "tools/list");
  } catch (error) {
    ok(`${label}：桥接会话失败（${error.message}）`, false);
  } finally {
    server.close();
  }
}

// endpoint 帧缺失时应报错退出（快速失败而非挂死）
{
  const server = http.createServer((req, res) => {
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(""); // 永不发 endpoint
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const code = await new Promise((resolve) => {
    const child = spawn(process.execPath, [BRIDGE, `http://127.0.0.1:${server.address().port}/sse`, "{}"], { stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "x" }) + "\n");
    const timer = setTimeout(() => { child.kill(); resolve("timeout"); }, 4000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c ?? "0"); });
    setTimeout(() => child.stdin.end(), 800);
  });
  ok("endpoint 缺失：stdin 结束后进程退出", code !== "timeout");
  server.close();
}

assert(pass + fail >= 3);
console.log(fail === 0 ? `all ${pass + fail} tests passed` : `${fail} FAILED of ${pass + fail}`);
process.exit(fail === 0 ? 0 : 1);
