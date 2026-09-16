// sse-bridge.mjs — stdio JSON-RPC（行分帧）<-> MCP SSE 旧协议（GET 流 + POST 消息端点）桥接。
// 用法：node sse-bridge.mjs <sse-url> [headers-json]
// 宿主 MCP 客户端按普通 stdio 服务器拉起本进程；进程内维持 SSE 长连接并双向转发。
const sseUrl = process.argv[2];
if (!sseUrl) {
  console.error("sse-bridge: missing <sse-url> argument");
  process.exit(1);
}
let extraHeaders = {};
try {
  extraHeaders = JSON.parse(process.argv[3] ?? "{}");
} catch (error) {
  console.error(`sse-bridge: invalid headers json: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

let messageUrl = null;
let closing = false;
const queue = [];

async function postLine(line) {
  if (messageUrl === null) return; // endpoint 未到，留在队列
  try {
    const response = await fetch(messageUrl, {
      method: "POST",
      headers: { "content-type": "application/json", ...extraHeaders },
      body: line
    });
    if (!(response.status >= 200 && response.status < 300)) {
      console.error(`sse-bridge: POST ${messageUrl} -> HTTP ${response.status}`);
    }
  } catch (error) {
    console.error(`sse-bridge: POST failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function flushQueue() {
  while (queue.length > 0 && messageUrl !== null) {
    void postLine(queue.shift());
  }
}

let stdinBuffer = "";
let activeReader = null;
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  stdinBuffer += chunk;
  let newline;
  while ((newline = stdinBuffer.indexOf("\n")) >= 0) {
    const line = stdinBuffer.slice(0, newline).trim();
    stdinBuffer = stdinBuffer.slice(newline + 1);
    if (line === "") continue;
    queue.push(line);
    flushQueue();
  }
});
process.stdin.on("end", () => {
  closing = true;
  // 宿主关闭 stdin（优雅卸载）：取消 SSE 流读取让主循环退出
  if (activeReader !== null) void activeReader.cancel().catch(() => {});
});

const stream = await fetch(sseUrl, {
  headers: { accept: "text/event-stream", ...extraHeaders }
});
if (!(stream.status >= 200 && stream.status < 300)) {
  console.error(`sse-bridge: GET ${sseUrl} -> HTTP ${stream.status} ${stream.statusText}`);
  process.exit(1);
}

const reader = stream.body.getReader();
activeReader = reader;
const decoder = new TextDecoder();
let frameBuffer = "";
while (!closing) {
  const chunk = await reader.read();
  if (chunk.done) break;
  // SSE 行终止符按规范归一为 \n（服务器可能发 \r\n、\r 或混合）
  frameBuffer += decoder.decode(chunk.value, { stream: true }).replace(/\r\n|\r/g, "\n");
  let separator;
  while ((separator = frameBuffer.indexOf("\n\n")) >= 0) {
    const frame = frameBuffer.slice(0, separator);
    frameBuffer = frameBuffer.slice(separator + 2);
    let event = "message";
    let data = "";
    for (const line of frame.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data += (data === "" ? "" : "\n") + line.slice(5).trim();
    }
    if (event === "endpoint") {
      if (data === "") continue;
      messageUrl = new URL(data, sseUrl).toString();
      flushQueue();
    } else if (data !== "") {
      let message;
      try {
        message = JSON.parse(data);
      } catch {
        continue;
      }
      process.stdout.write(JSON.stringify(message) + "\n");
    }
  }
}
process.exit(0);
