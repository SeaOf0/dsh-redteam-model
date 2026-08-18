// src/index.ts
import "@deepseek-ai/schemastery";
import { installSettingsSection, settingsNamespace } from "@deepseek-ai/dsh-settings";
import * as mcpClient from "@deepseek-ai/dsh-mcp-client";

// src/types.ts
import z from "@deepseek-ai/schemastery";
var ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
var DEFAULT_TOOL_CALL_TIMEOUT_MS = 6e4;
var ServerEntrySchema = z.object({
  id: z.string().required().pattern(ID_PATTERN),
  enabled: z.boolean().default(true),
  name: z.string().default(""),
  transport: z.union([z.const("stdio"), z.const("streamable-http")]).default("stdio"),
  command: z.string().default(""),
  argsLine: z.string().default(""),
  env: z.dict(z.string()),
  cwd: z.string().default(""),
  url: z.string().default(""),
  headers: z.dict(z.string()),
  toolCallTimeoutMs: z.number().step(1e3).min(1e3).max(36e5).default(DEFAULT_TOOL_CALL_TIMEOUT_MS),
  failOnStartupError: z.boolean().default(false)
});
var Config = z.object({
  servers: z.array(ServerEntrySchema).default([])
});
function splitArgs(line2) {
  const tokens = [];
  let current = "";
  let quote;
  let started = false;
  for (let index = 0; index < line2.length; index += 1) {
    const char = line2[index];
    if (quote === void 0) {
      if (char === " " || char === "	") {
        if (started) {
          tokens.push(current);
          current = "";
          started = false;
        }
        continue;
      }
      if (char === "\\" && index + 1 < line2.length) {
        current += line2[++index];
        started = true;
        continue;
      }
      if (char === "'" || char === '"') {
        quote = char;
        started = true;
        continue;
      }
      current += char;
      started = true;
    } else if (quote === "'") {
      if (char === "'") quote = void 0;
      else current += char;
    } else {
      if (char === "\\" && index + 1 < line2.length) {
        current += line2[++index];
      } else if (char === '"') {
        quote = void 0;
      } else {
        current += char;
      }
    }
  }
  if (started) tokens.push(current);
  return tokens;
}
function toMcpClientConfig(server) {
  const base = {
    serverName: server.name,
    toolCallTimeoutMs: server.toolCallTimeoutMs,
    failOnStartupError: server.failOnStartupError
  };
  if (server.transport === "stdio") {
    return {
      ...base,
      transport: "stdio",
      command: server.command,
      args: splitArgs(server.argsLine),
      env: server.env,
      cwd: server.cwd
    };
  }
  return {
    ...base,
    transport: "streamable-http",
    url: server.url,
    headers: server.headers
  };
}
function validateSection(value) {
  const names = /* @__PURE__ */ new Set();
  for (const server of value.servers) {
    if (!server.enabled) continue;
    if (names.has(server.name)) {
      throw new Error(`mcp-studio: two enabled servers share the name "${server.name}" \u2014 server names must be unique`);
    }
    if (server.name.trim() === "") {
      throw new Error(`mcp-studio: an enabled server has no name`);
    }
    names.add(server.name);
    if (server.transport === "stdio" && server.command.trim() === "") {
      throw new Error(`mcp-studio: stdio server "${server.name}" has no command`);
    }
    if (server.transport === "streamable-http") {
      if (server.url.trim() === "") throw new Error(`mcp-studio: server "${server.name}" has no url`);
      let parsed;
      try {
        parsed = new URL(server.url);
      } catch {
        throw new Error(`mcp-studio: server "${server.name}" url "${server.url}" is not a valid URL`);
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`mcp-studio: server "${server.name}" url must use http or https`);
      }
    }
  }
}

// src/settings-rpc.ts
var STUDIO_CHANNEL = "/dsh-mcp-studio";
var WRITABLE_FIELDS = /* @__PURE__ */ new Set(["servers"]);
function ok(value) {
  return { ok: true, value };
}
function failure(error, ns) {
  return {
    ok: false,
    error: {
      code: "settings-rejected",
      message: error instanceof Error ? error.message : String(error),
      details: { ns }
    }
  };
}
function badRequest(message) {
  return { ok: false, error: { code: "bad-request", message, details: { issues: [] } } };
}
function asObject(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("payload must be an object");
  return value;
}
function descriptor(settings, ns) {
  const view = settings.describe({ redactSecrets: true }).find((candidate) => candidate.ns === ns);
  if (view === void 0) throw new Error(`settings namespace "${ns}" is unavailable`);
  return {
    status: "ready",
    value: view.value,
    ...view.base === void 0 ? {} : { base: view.base },
    ...view.user === void 0 ? {} : { user: view.user },
    revision: view.revision,
    writable: settings.writable,
    mode: "host",
    ...view.applies === void 0 ? {} : { applies: view.applies }
  };
}
function createExecutionRing(max = 200) {
  const records = [];
  return {
    max,
    push: (record) => {
      records.push(record);
      if (records.length > max) records.splice(0, records.length - max);
    },
    recent: (limit) => records.slice(-limit).reverse(),
    clear: () => {
      records.splice(0, records.length);
    }
  };
}
function asToolsViewHandle(view) {
  if (typeof view !== "object" || view === null) return void 0;
  const visible = view.visible;
  if (!(visible instanceof Map)) return void 0;
  return view;
}
function createStatusHandler(section, viewOf, tracker, executions) {
  return async () => {
    const current = section();
    const view = asToolsViewHandle(viewOf());
    const servers = [];
    let connected = 0;
    let totalTools = 0;
    for (const server of current.servers) {
      const prefix = `mcp__${server.name}__`;
      const tools = [];
      if (view !== void 0 && server.enabled) {
        for (const [name2, definition] of view.visible) {
          if (!name2.startsWith(prefix)) continue;
          tools.push({ name: name2.slice(prefix.length), description: typeof definition.description === "string" ? definition.description : "" });
        }
        tools.sort((left, right) => left.name.localeCompare(right.name));
      }
      const note = tracker.states.get(server.id);
      let state;
      let error;
      if (!server.enabled) state = "disabled";
      else if (tools.length > 0) state = "connected";
      else if (note?.state === "error") {
        state = "error";
        error = note.error;
      } else if (note?.state === "mounting") state = "mounting";
      else state = "unreachable";
      if (state === "connected") connected += 1;
      totalTools += tools.length;
      servers.push({
        id: server.id,
        name: server.name,
        transport: server.transport,
        state,
        ...error === void 0 ? {} : { error },
        toolCount: tools.length,
        tools
      });
    }
    const enabled = servers.filter((server) => server.state !== "disabled").length;
    return ok({
      servers,
      summary: { total: servers.length, enabled, connected, tools: totalTools },
      ...executions === void 0 ? {} : { executions: executions.recent(executions.max), execCapacity: executions.max }
    });
  };
}
function registerStudioRpc(connection, settings, ns, status, diagnose, clearExecutions) {
  connection.rpc.handle(STUDIO_CHANNEL, async (endpoint, rawPayload) => {
    if (endpoint === "status") return status();
    if (endpoint === "executions/clear") {
      if (clearExecutions === void 0) return badRequest("execution log unavailable");
      clearExecutions();
      return ok({ cleared: true });
    }
    if (endpoint === "diagnose") {
      if (diagnose === void 0) return badRequest("diagnose unavailable");
      const id = typeof rawPayload?.id === "string" ? rawPayload.id : "";
      return diagnose(id);
    }
    try {
      if (endpoint === "settings/get") return ok(descriptor(settings, ns));
      if (endpoint === "settings/mutate") {
        if (!settings.writable) throw new Error("DSH settings are read-only");
        const payload = asObject(rawPayload);
        const rawOps = payload.ops;
        if (!Array.isArray(rawOps) || rawOps.length === 0 || rawOps.length > 4) throw new Error("ops must contain 1..4 settings edits");
        const ops = rawOps.map((raw) => {
          const op = asObject(raw);
          const path = op.path;
          if (!Array.isArray(path) || path.length !== 1 || !WRITABLE_FIELDS.has(String(path[0]))) {
            throw new Error(`unsupported mcp-studio settings path: ${JSON.stringify(path)}`);
          }
          if (op.op === "unset") return { op: "unset", path: [String(path[0])] };
          if (op.op !== "set") throw new Error(`unsupported settings operation: ${String(op.op)}`);
          return { op: "set", path: [String(path[0])], value: op.value };
        });
        const revision = payload.expectedRevision === void 0 ? void 0 : Number(payload.expectedRevision);
        await settings.mutate(ns, ops, revision);
        return ok(descriptor(settings, ns));
      }
      return badRequest(`unknown endpoint: ${endpoint}`);
    } catch (error) {
      return failure(error, ns);
    }
  }, { authority: "loopback" });
}

// src/diagnose.ts
import { spawn } from "node:child_process";
var TIMEOUT_MS = 1e4;
function line(obj) {
  return `${JSON.stringify(obj)}
`;
}
function stdioTransport(server) {
  const args = splitArgs(server.argsLine);
  const child = spawn(server.command, args, {
    cwd: server.cwd === "" ? void 0 : server.cwd,
    env: { ...process.env, ...server.env },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let buffer = "";
  const listeners = [];
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const frame = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (frame === "") continue;
      try {
        const message = JSON.parse(frame);
        for (const listener of listeners) listener(message);
      } catch {
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", () => {
  });
  return {
    send: (payload) => child.stdin.write(payload),
    onMessage: (handler) => listeners.push(handler),
    close: () => {
      child.kill();
    }
  };
}
async function httpTransport(server, messages) {
  const url = new URL(server.url);
  const responses = [];
  for (const message of messages) {
    const isNotification = typeof message.method === "string" && message.id === void 0;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...server.headers
      },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (isNotification) continue;
    if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);
    const contentType = response.headers.get("content-type") ?? "";
    const text = await response.text();
    if (text.trim() === "") throw new Error(`empty response body from ${server.url}`);
    if (contentType.includes("text/event-stream")) {
      for (const frame of text.split("\n")) {
        if (!frame.startsWith("data:")) continue;
        const payload = frame.slice(5).trim();
        if (payload === "") continue;
        try {
          responses.push(JSON.parse(payload));
        } catch {
        }
      }
    } else {
      responses.push(JSON.parse(text));
    }
  }
  return responses;
}
async function diagnoseServer(server) {
  const started = Date.now();
  try {
    if (server.transport === "streamable-http") {
      const messages = [
        { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "dsh-mcp-studio-diag", version: "0.1.0" } } },
        { jsonrpc: "2.0", method: "notifications/initialized" },
        { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }
      ];
      const responses = await httpTransport(server, messages);
      const init = responses.find((message) => message.id === 1);
      const tools = responses.find((message) => message.id === 2);
      if (init === void 0 || init.result === void 0 && init.error !== void 0) {
        throw new Error(`initialize failed: ${JSON.stringify(init?.error ?? "no response")}`);
      }
      const info = init.result ?? {};
      const serverInfo = info.serverInfo ?? {};
      const toolList = Array.isArray(tools?.result?.tools) ? (tools?.result).tools.length : void 0;
      return {
        ok: true,
        elapsedMs: Date.now() - started,
        protocolVersion: typeof info.protocolVersion === "string" ? info.protocolVersion : void 0,
        serverName: typeof serverInfo.name === "string" ? serverInfo.name : void 0,
        serverVersion: typeof serverInfo.version === "string" ? serverInfo.version : void 0,
        toolCount: toolList
      };
    }
    return await new Promise((resolve, reject) => {
      const transport = stdioTransport(server);
      const timer = setTimeout(() => {
        transport.close();
        reject(new Error(`handshake timed out after ${TIMEOUT_MS}ms`));
      }, TIMEOUT_MS);
      let protocolVersion;
      let serverName;
      let serverVersion;
      let toolCount;
      transport.onMessage((message) => {
        if (message.id === 1 && message.result !== void 0) {
          const info = message.result;
          const serverInfo = info.serverInfo ?? {};
          protocolVersion = typeof info.protocolVersion === "string" ? info.protocolVersion : void 0;
          serverName = typeof serverInfo.name === "string" ? serverInfo.name : void 0;
          serverVersion = typeof serverInfo.version === "string" ? serverInfo.version : void 0;
          transport.send(line({ jsonrpc: "2.0", method: "notifications/initialized" }));
          transport.send(line({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
        } else if (message.id === 2 && message.result !== void 0) {
          const tools = message.result.tools;
          toolCount = Array.isArray(tools) ? tools.length : 0;
          clearTimeout(timer);
          transport.close();
          resolve({
            ok: true,
            elapsedMs: Date.now() - started,
            ...protocolVersion === void 0 ? {} : { protocolVersion },
            ...serverName === void 0 ? {} : { serverName },
            ...serverVersion === void 0 ? {} : { serverVersion },
            toolCount
          });
        } else if (message.error !== void 0) {
          clearTimeout(timer);
          transport.close();
          reject(new Error(JSON.stringify(message.error)));
        }
      });
      transport.onMessage(() => {
      });
      transport.send(line({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "dsh-mcp-studio-diag", version: "0.1.0" } } }));
    });
  } catch (error) {
    return {
      ok: false,
      elapsedMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

// src/index.ts
var name = "dsh-mcp-studio";
var inject = ["tools"];
var STUDIO_SETTINGS_NAMESPACE = settingsNamespace("mcp-studio");
function signatureOf(server) {
  return JSON.stringify(toMcpClientConfig(server));
}
function apply(ctx, config) {
  let current = () => config;
  let alive = true;
  const mounts = /* @__PURE__ */ new Map();
  const tracker = { states: /* @__PURE__ */ new Map() };
  const reconcile = () => {
    if (!alive) return;
    const section = current();
    const wanted = /* @__PURE__ */ new Map();
    for (const server of section.servers) {
      if (server.enabled) wanted.set(server.id, server);
    }
    for (const [id, mount] of [...mounts]) {
      const server = wanted.get(id);
      if (server === void 0 || signatureOf(server) !== mount.signature) {
        mount.dispose();
        mounts.delete(id);
        tracker.states.delete(id);
      }
    }
    for (const [id, server] of wanted) {
      if (mounts.has(id)) continue;
      const clientConfig = toMcpClientConfig(server);
      tracker.states.set(id, { state: "mounting" });
      let fiber;
      try {
        fiber = ctx.plugin(mcpClient, clientConfig);
      } catch (error) {
        ctx.logger.warn('mcp-studio: could not mount server "%s": %s', server.name, String(error));
        tracker.states.set(id, { state: "error", error: String(error) });
        continue;
      }
      mounts.set(id, { dispose: () => fiber.dispose(), signature: JSON.stringify(clientConfig) });
      Promise.resolve(fiber).then(
        () => {
          if (tracker.states.get(id)?.state === "mounting") tracker.states.set(id, { state: "mounted" });
        },
        (error) => {
          tracker.states.set(id, { state: "error", error: error instanceof Error ? error.message : String(error) });
          ctx.logger.warn('mcp-studio: server "%s" failed to start: %s', server.name, String(error instanceof Error ? error.message : error));
        }
      );
    }
    for (const server of section.servers) {
      if (!mounts.has(server.id)) tracker.states.delete(server.id);
    }
  };
  ctx.effect(() => () => {
    alive = false;
    for (const mount of mounts.values()) {
      try {
        mount.dispose();
      } catch (error) {
        ctx.logger.warn("mcp-studio: mount disposal failed: %s", String(error));
      }
    }
    mounts.clear();
    tracker.states.clear();
  }, "mcp-studio: lifecycle");
  installSettingsSection(ctx, STUDIO_SETTINGS_NAMESPACE, Config, config, {
    setSource: (source) => {
      current = source;
    },
    onChange: () => {
      reconcile();
    },
    validate: validateSection
  });
  const executions = createExecutionRing(200);
  const inflight = /* @__PURE__ */ new Map();
  ctx.effect(() => {
    const sweeper = setInterval(() => {
      const cutoff = Date.now() - 10 * 6e4;
      for (const [key, entry] of [...inflight]) {
        if (entry.at < cutoff) inflight.delete(key);
      }
    }, 6e4);
    return () => {
      clearInterval(sweeper);
    };
  }, "mcp-studio: inflight sweep");
  ctx.on("session/event", ((session, event) => {
    if (event.type === "tool/call") {
      const name2 = typeof event.data.name === "string" ? event.data.name : "";
      if (!name2.startsWith("mcp__")) return;
      const callId = typeof event.data.callId === "string" ? event.data.callId : "";
      const sessionId = String(session.id ?? "");
      inflight.set(`${sessionId}:${event.time}:${callId}`, {
        server: name2.split("__")[1] ?? "",
        tool: name2,
        at: event.time
      });
      return;
    }
    if (event.type === "tool/result") {
      const message = event.data.message ?? {};
      const callId = typeof message.source?.callId === "string" && message.source?.kind === "tool" ? message.source.callId : (message.content ?? []).find((block) => typeof block?.toolCallId === "string")?.toolCallId;
      if (typeof callId !== "string") return;
      const sessionId = String(session.id ?? "");
      for (const [key, entry] of [...inflight]) {
        if (!key.startsWith(`${sessionId}:`) || !key.endsWith(`:${callId}`)) continue;
        inflight.delete(key);
        const isError = (message.content ?? []).some((block) => block?.isError === true) || event.data.error !== void 0;
        const errorInfo = event.data.error;
        executions.push({
          at: entry.at,
          server: entry.server,
          tool: entry.tool,
          durationMs: Math.max(0, event.time - entry.at),
          ok: !isError,
          ...isError && errorInfo !== void 0 ? { error: JSON.stringify(errorInfo).slice(0, 300) } : {}
        });
      }
    }
  }));
  ctx.inject(["connection", "settings"], (web) => {
    const { connection, settings } = web;
    const status = createStatusHandler(
      () => current(),
      () => ctx.get("tools")?.view(void 0),
      tracker,
      executions
    );
    const diagnose = async (id) => {
      const server = current().servers.find((row) => row.id === id);
      if (server === void 0) {
        return { ok: false, error: { code: "bad-request", message: `unknown server row "${id}"`, details: {} } };
      }
      const report = await diagnoseServer(server);
      return { ok: true, value: report };
    };
    registerStudioRpc(connection, settings, STUDIO_SETTINGS_NAMESPACE, status, diagnose, () => executions.clear());
  });
  reconcile();
}
export {
  STUDIO_SETTINGS_NAMESPACE,
  apply,
  inject,
  name
};
