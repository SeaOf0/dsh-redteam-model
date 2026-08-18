window.__ModuleLoader__.load({ id: "@dsh-external/dsh-mcp-studio", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name2 in all)
    __defProp(target, name2, { get: all[name2], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client/index.ts
var index_exports = {};
__export(index_exports, {
  apply: () => apply,
  inject: () => inject,
  name: () => name
});
module.exports = __toCommonJS(index_exports);

// src/client/McpStudioPage.tsx
var import_react3 = require("react");

// src/client/components.tsx
var import_react = require("react");
var import_jsx_runtime = require("react/jsx-runtime");
function useStoreState(store) {
  const [state, setState] = (0, import_react.useState)(() => store.getSnapshot());
  (0, import_react.useEffect)(() => store.subscribe(() => setState(store.getSnapshot())), [store]);
  return state;
}
function Field(props) {
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "dsh-mcs-field", children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: props.label }),
    props.children,
    props.hint !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: props.hint })
  ] });
}
function PairEditor(props) {
  const { t } = props;
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "dsh-mcs-pairs", children: [
    props.pairs.map((pair, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "dsh-mcs-pairrow", children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
        "input",
        {
          "aria-label": "key",
          placeholder: "KEY",
          value: pair.key,
          onChange: (event) => props.onChange(props.pairs.map((entry, i) => i === index ? { ...entry, key: event.target.value } : entry))
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
        "input",
        {
          "aria-label": "value",
          placeholder: t("pairValuePlaceholder"),
          value: pair.value,
          onChange: (event) => props.onChange(props.pairs.map((entry, i) => i === index ? { ...entry, value: event.target.value } : entry))
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--danger", onClick: () => props.onChange(props.pairs.filter((_, i) => i !== index)), children: t("removePair") })
    ] }, index)),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: () => props.onChange([...props.pairs, { key: "", value: "" }]), children: t("addPair") })
  ] });
}
function ToggleSwitch(props) {
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(
    "label",
    {
      className: "dsh-mcs-switch",
      title: props.label,
      onClick: (event) => event.stopPropagation(),
      children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          "input",
          {
            type: "checkbox",
            checked: props.checked,
            "aria-label": props.label,
            onChange: (event) => {
              event.stopPropagation();
              props.onChange(event.target.checked);
            },
            onClick: (event) => event.stopPropagation()
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", {})
      ]
    }
  );
}

// src/client/ServerCard.tsx
var import_react2 = require("react");

// src/client/mcp-json.ts
var DEFAULT_TIMEOUT_MS = 6e4;
function quoteArg(token) {
  if (token === "") return '""';
  if (!/[\s"']/.test(token)) return token;
  return `"${token.replace(/(["\\])/g, "\\$1")}"`;
}
function argsToLine(args) {
  return args.filter((arg) => typeof arg === "string").map((arg) => quoteArg(arg)).join(" ");
}
function toPairs(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return [];
  return Object.entries(value).filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean").map(([key, v]) => ({ key, value: String(v) }));
}
function str(value) {
  return typeof value === "string" ? value : "";
}
function parseServerEntry(name2, raw) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return void 0;
  const entry = raw;
  const declared = str(entry.type).toLowerCase();
  const args = Array.isArray(entry.args) ? entry.args : [];
  const command = str(entry.command);
  const url = str(entry.url);
  const isHttp = declared === "http" || declared === "sse" || declared === "streamable-http" || command === "" && url !== "";
  if (!isHttp && command === "") return void 0;
  return {
    id: "",
    enabled: entry.disabled !== true,
    name: name2,
    transport: isHttp ? "streamable-http" : "stdio",
    command: isHttp ? "" : command,
    argsLine: isHttp ? "" : argsToLine(args),
    env: isHttp ? [] : toPairs(entry.env),
    cwd: isHttp ? "" : str(entry.cwd),
    url: isHttp ? url : "",
    headers: isHttp ? toPairs(entry.headers) : [],
    toolCallTimeoutMs: DEFAULT_TIMEOUT_MS,
    failOnStartupError: false
  };
}
function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
var MCP_JSON_TEMPLATE = `{
  "mcpServers": {
    "example": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"],
      "env": {}
    }
  }
}`;
function formatMcpJson(text) {
  const trimmed = text.trim();
  if (trimmed === "") return { error: "empty input" };
  try {
    const document2 = JSON.parse(trimmed);
    return { text: `${JSON.stringify(document2, null, 2)}
` };
  } catch (error) {
    return { error: `invalid JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
}
function lineToArgs(line) {
  const tokens = [];
  let current = "";
  let quote;
  let started = false;
  for (const char of line) {
    if (quote === void 0) {
      if (char === " " || char === "	") {
        if (started) {
          tokens.push(current);
          current = "";
          started = false;
        }
        continue;
      }
      if (char === '"' || char === "'") {
        quote = char;
        started = true;
        continue;
      }
      current += char;
      started = true;
    } else if (char === quote) {
      quote = void 0;
    } else {
      current += char;
    }
  }
  if (started) tokens.push(current);
  return tokens;
}
function pairsToRecord(pairs) {
  const record = {};
  for (const pair of pairs) {
    if (pair.key.trim() !== "") record[pair.key] = pair.value;
  }
  return record;
}
function serversToMcpJson(servers) {
  const mcpServers = {};
  for (const server of servers) {
    mcpServers[server.name] = server.transport === "stdio" ? {
      command: server.command,
      ...server.argsLine.trim() === "" ? {} : { args: lineToArgs(server.argsLine) },
      ...Object.keys(pairsToRecord(server.env)).length === 0 ? {} : { env: pairsToRecord(server.env) },
      ...server.cwd.trim() === "" ? {} : { cwd: server.cwd }
    } : {
      type: "http",
      url: server.url,
      ...Object.keys(pairsToRecord(server.headers)).length === 0 ? {} : { headers: pairsToRecord(server.headers) }
    };
  }
  return `${JSON.stringify({ mcpServers }, null, 2)}
`;
}
function parseMcpJson(text, existing = []) {
  const trimmed = text.trim();
  if (trimmed === "") return { error: "empty input" };
  let document2;
  try {
    document2 = JSON.parse(trimmed);
  } catch (error) {
    return { error: `invalid JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (!isObject(document2)) return { error: "expected a JSON object" };
  const warnings = [];
  const collect = (map) => {
    const servers2 = [];
    for (const [rawName, rawEntry] of Object.entries(map)) {
      if (!isObject(rawEntry)) continue;
      if (rawName === "_meta" || rawName === "inputs" || rawName.startsWith("$")) continue;
      const draft = parseServerEntry(rawName, rawEntry);
      if (draft === void 0) {
        warnings.push(`skipped "${rawName}": no command (stdio) or url (http)`);
        continue;
      }
      servers2.push(draft);
    }
    return servers2;
  };
  const resolveMap = (value) => {
    const container = value.mcpServers ?? value.servers;
    if (isObject(container)) return collect(container);
    const single = parseServerEntry("", value);
    if (single !== void 0) return [single];
    const bare = collect(value);
    if (bare.length > 0) return bare;
    const children = Object.values(value).filter(isObject);
    if (children.length === 1) {
      const nested = resolveMap(children[0]);
      if (nested !== void 0 && nested.length > 0) return nested;
    }
    return void 0;
  };
  let servers;
  try {
    servers = resolveMap(document2);
  } catch {
    servers = void 0;
  }
  if (servers === void 0 || servers.length === 0) {
    return {
      error: warnings[0] ?? 'no server entries found: expected {"mcpServers": {...}}, {"servers": {...}}, a bare {name: config} map, or one server object'
    };
  }
  const used = new Set(existing);
  const uniqueName = (wanted) => {
    let base = wanted === "" ? "server" : wanted.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 32);
    if (base === "") base = "server";
    if (!used.has(base)) {
      used.add(base);
      return base;
    }
    let n = 2;
    while (used.has(`${base}-${n}`)) n += 1;
    base = `${base}-${n}`;
    used.add(base);
    return base;
  };
  return { servers: servers.map((server) => ({ ...server, name: uniqueName(server.name) })), warnings };
}

// src/client/ServerCard.tsx
var import_jsx_runtime2 = require("react/jsx-runtime");
function transportDisplay(value) {
  return value === "stdio" ? "stdio" : "http";
}
function parseTransportInput(text) {
  const normalized = text.trim().toLowerCase().replace(/[\s_-]/g, "");
  if (normalized === "") return void 0;
  if (normalized === "stdio") return "stdio";
  if (normalized === "http" || normalized === "sse" || normalized === "streamablehttp") return "streamable-http";
  return void 0;
}
var stateLabel = {
  connected: "stateConnected",
  mounting: "stateMounting",
  unreachable: "stateUnreachable",
  error: "stateError",
  disabled: "stateDisabled"
};
var stateClass = {
  connected: "dsh-mcs-dot--ok",
  mounting: "dsh-mcs-dot--busy",
  unreachable: "",
  error: "dsh-mcs-dot--err",
  disabled: ""
};
var stateTextClass = {
  connected: "dsh-mcs-state--ok",
  mounting: "dsh-mcs-state--busy",
  unreachable: "dsh-mcs-state--off",
  error: "dsh-mcs-state--err",
  disabled: "dsh-mcs-state--off"
};
function ToolPopover(props) {
  const { t } = props;
  const [filter, setFilter] = (0, import_react2.useState)("");
  const tools = (0, import_react2.useMemo)(() => {
    const needle = filter.trim().toLowerCase();
    if (needle === "") return props.live.tools;
    return props.live.tools.filter((tool) => tool.name.toLowerCase().includes(needle) || tool.description.toLowerCase().includes(needle));
  }, [filter, props.live.tools]);
  return /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(import_jsx_runtime2.Fragment, { children: [
    /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-popbackdrop", onClick: (event) => {
      event.stopPropagation();
      props.onClose();
    } }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(
      "div",
      {
        className: "dsh-mcs-pop",
        role: "dialog",
        "aria-label": t("toolsTitle"),
        style: { position: "fixed", top: props.pos.top, left: props.pos.left, width: props.pos.width, maxHeight: props.pos.maxHeight },
        onClick: (event) => event.stopPropagation(),
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-tools-head", children: [
            /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("h4", { className: "dsh-mcs-tools-title", children: [
              props.live.name,
              " \xB7 ",
              props.live.toolCount,
              " ",
              t("toolsUnit")
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
              "input",
              {
                className: "dsh-mcs-search",
                autoFocus: true,
                placeholder: t("toolsSearchPlaceholder"),
                value: filter,
                onChange: (event) => setFilter(event.target.value),
                onClick: (event) => event.stopPropagation()
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-toollist", children: tools.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-tools-empty", children: filter.trim() === "" ? t("toolsWaiting") : t("toolsEmpty") }) : tools.map((tool) => /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-tool", title: tool.description, children: [
            /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("code", { children: tool.name }),
            /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: tool.description })
          ] }, tool.name)) })
        ]
      }
    )
  ] });
}
function ServerCard(props) {
  const { server, live, t } = props;
  const set = (patch) => props.onUpdate({ ...server, ...patch });
  const [transportText, setTransportText] = (0, import_react2.useState)(() => transportDisplay(server.transport));
  const [copied, setCopied] = (0, import_react2.useState)(false);
  const [diagBusy, setDiagBusy] = (0, import_react2.useState)(false);
  const [toolsOpen, setToolsOpen] = (0, import_react2.useState)(false);
  const badgeRef = (0, import_react2.useRef)(null);
  const [popPos, setPopPos] = (0, import_react2.useState)(void 0);
  const [diag, setDiag] = (0, import_react2.useState)(void 0);
  const runDiagnose = () => {
    if (props.diagnose === void 0 || diagBusy) return;
    setDiagBusy(true);
    setDiag(void 0);
    void props.diagnose(server.id).then((report) => {
      setDiag(report);
      setDiagBusy(false);
    }, () => {
      setDiag({ error: "request failed" });
      setDiagBusy(false);
    });
  };
  (0, import_react2.useEffect)(() => {
    setTransportText(transportDisplay(server.transport));
  }, [server.transport]);
  (0, import_react2.useEffect)(() => {
    if (live?.state !== "connected") setToolsOpen(false);
  }, [live?.state]);
  const reposition = (0, import_react2.useCallback)((initial) => {
    const badge = badgeRef.current;
    const card = badge?.closest(".dsh-mcs-card");
    if (badge === null || card === null) return;
    const badgeRect = badge.getBoundingClientRect();
    if (!initial && (badgeRect.bottom < 0 || badgeRect.top > window.innerHeight)) {
      setToolsOpen(false);
      return;
    }
    const cardRect = card.getBoundingClientRect();
    const margin = 8;
    const gap = 6;
    const width = Math.min(520, window.innerWidth - margin * 2);
    const desired = Math.min(380, window.innerHeight - margin * 2);
    let top = badgeRect.bottom + gap;
    if (top + desired > window.innerHeight - margin) top = badgeRect.top - gap - desired;
    if (top < margin) top = margin;
    const maxHeight = Math.max(160, Math.min(desired, window.innerHeight - margin - top));
    let left = cardRect.right - width;
    if (left < margin) left = margin;
    if (left + width > window.innerWidth - margin) left = window.innerWidth - margin - width;
    setPopPos((previous) => previous !== void 0 && previous.top === top && previous.left === left && previous.width === width && previous.maxHeight === maxHeight ? previous : { top, left, width, maxHeight });
  }, []);
  (0, import_react2.useEffect)(() => {
    if (!toolsOpen) {
      setPopPos(void 0);
      return;
    }
    reposition(true);
    const re = (event) => {
      const target = event !== void 0 && event.type === "scroll" ? event.target : null;
      if (target !== null && typeof target.closest === "function" && target.closest(".dsh-mcs-pop") !== null) return;
      reposition(false);
    };
    window.addEventListener("resize", re);
    window.addEventListener("scroll", re, true);
    return () => {
      window.removeEventListener("resize", re);
      window.removeEventListener("scroll", re, true);
    };
  }, [toolsOpen, reposition]);
  const transportInvalid = parseTransportInput(transportText) === void 0 && transportText.trim() !== "";
  const state = live === void 0 ? server.enabled ? "mounting" : "disabled" : live.state;
  const summary = server.transport === "stdio" ? `${server.command}${server.argsLine.trim() === "" ? "" : ` ${server.argsLine.trim()}`}` : server.url;
  const toolCount = live?.toolCount ?? 0;
  return /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: props.open ? "dsh-mcs-card is-open" : server.enabled ? "dsh-mcs-card" : "dsh-mcs-card is-off", children: [
    toolsOpen && live !== void 0 && live.state === "connected" && popPos !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(ToolPopover, { live, t, pos: popPos, onClose: () => setToolsOpen(false) }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(
      "div",
      {
        className: "dsh-mcs-card-head",
        role: "button",
        tabIndex: 0,
        "aria-expanded": props.open,
        title: server.name === "" ? void 0 : `${server.name} \xB7 ${summary}`,
        onClick: props.onToggle,
        onKeyDown: (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            props.onToggle();
          }
        },
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: `dsh-mcs-dot ${stateClass[state]}` }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: "dsh-mcs-name", children: server.name === "" ? t("unnamedServer") : server.name }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: server.transport === "stdio" ? "dsh-mcs-chip" : "dsh-mcs-chip dsh-mcs-chip--http", children: server.transport === "stdio" ? "stdio" : "http" }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: "dsh-mcs-cmd", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("code", { children: summary }) }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: `dsh-mcs-state ${stateTextClass[state]}`, children: t(stateLabel[state]) }),
          state === "connected" && /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(
            "button",
            {
              ref: (node) => {
                badgeRef.current = node;
              },
              type: "button",
              className: "dsh-mcs-toolscount dsh-mcs-toolscount--btn",
              title: t("toolsPreviewHint"),
              onClick: (event) => {
                event.stopPropagation();
                setToolsOpen((open) => !open);
              },
              children: [
                toolCount,
                " ",
                t("toolsUnit")
              ]
            }
          ),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(ToggleSwitch, { checked: server.enabled, label: t("serverEnabled"), onChange: (enabled) => set({ enabled }) }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
            "button",
            {
              type: "button",
              className: "dsh-mcs-iconbtn",
              title: t("removeServer"),
              "aria-label": t("removeServer"),
              onClick: (event) => {
                event.stopPropagation();
                props.onRemove();
              },
              children: "\xD7"
            }
          ),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("button", { type: "button", className: "dsh-mcs-chevron", "aria-hidden": true, tabIndex: -1, children: "\u25B6" })
        ]
      }
    ),
    state === "error" && live?.error !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-carderr", children: live.error }),
    props.open && /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-body", onClick: (event) => event.stopPropagation(), children: [
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-grid", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("serverName"), hint: t("serverNameHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("input", { value: server.name, onChange: (event) => set({ name: event.target.value }) }) }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("transport"), hint: transportInvalid ? t("transportInvalid") : t("transportHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          "input",
          {
            value: transportText,
            spellCheck: false,
            placeholder: "stdio | http",
            onChange: (event) => {
              const text = event.target.value;
              setTransportText(text);
              const parsed = parseTransportInput(text);
              if (parsed !== void 0 && parsed !== server.transport) set({ transport: parsed });
            }
          }
        ) }),
        server.transport === "stdio" ? /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(import_jsx_runtime2.Fragment, { children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("command"), hint: t("commandHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("input", { value: server.command, onChange: (event) => set({ command: event.target.value }) }) }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("argsLine"), hint: t("argsLineHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("input", { value: server.argsLine, onChange: (event) => set({ argsLine: event.target.value }) }) }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("cwd"), hint: t("cwdHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("input", { value: server.cwd, onChange: (event) => set({ cwd: event.target.value }) }) })
        ] }) : /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("url"), hint: t("urlHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("input", { value: server.url, onChange: (event) => set({ url: event.target.value }) }) }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("toolCallTimeoutMs"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          "input",
          {
            type: "number",
            min: 1e3,
            step: 1e3,
            value: server.toolCallTimeoutMs,
            onChange: (event) => {
              const value = Number.parseInt(event.target.value, 10);
              set({ toolCallTimeoutMs: Number.isFinite(value) ? Math.max(1e3, value) : 6e4 });
            }
          }
        ) })
      ] }),
      server.transport === "stdio" ? /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("env"), hint: t("envHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(PairEditor, { pairs: server.env, t, onChange: (env) => set({ env }) }) }) : /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(Field, { label: t("headers"), hint: t("headersHint"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(PairEditor, { pairs: server.headers, t, onChange: (headers) => set({ headers }) }) }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-check", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          "input",
          {
            type: "checkbox",
            id: `mcs-fail-${server.id}`,
            checked: server.failOnStartupError,
            onChange: (event) => set({ failOnStartupError: event.target.checked })
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("label", { htmlFor: `mcs-fail-${server.id}`, children: t("failOnStartupError") }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("small", { children: t("failOnStartupErrorHint") })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-toolbar", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          "button",
          {
            type: "button",
            className: "dsh-mcs-btn dsh-mcs-btn--ghost",
            onClick: () => {
              const json = serversToMcpJson([server]);
              void navigator.clipboard?.writeText(json).then(
                () => {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1600);
                },
                () => setCopied(false)
              );
            },
            children: copied ? t("copied") : t("copyThisServer")
          }
        ),
        props.diagnose !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", disabled: diagBusy, onClick: runDiagnose, children: diagBusy ? /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: "dsh-mcs-spin" }) : t("testConnection") })
      ] }),
      diag !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-diag", children: "ok" in diag && diag.ok ? /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-diag-grid", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-diag-cell", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("diagElapsed") }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("strong", { children: [
            diag.elapsedMs,
            " ms"
          ] })
        ] }),
        diag.protocolVersion !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-diag-cell", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("diagProtocol") }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("strong", { children: diag.protocolVersion })
        ] }),
        diag.serverName !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-diag-cell", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("diagServer") }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("strong", { children: [
            diag.serverName,
            diag.serverVersion !== void 0 ? ` ${diag.serverVersion}` : ""
          ] })
        ] }),
        diag.toolCount !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-mcs-diag-cell", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("diagTools") }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("strong", { children: diag.toolCount })
        ] })
      ] }) : /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-mcs-diag-error", children: "error" in diag ? diag.error : "failed" }) })
    ] })
  ] });
}

// src/client/presets.ts
var SERVER_PRESETS = [
  {
    id: "everything",
    label: "Everything",
    description: "MCP \u5B98\u65B9\u6D4B\u8BD5\u670D\u52A1\u5668\uFF0C\u542B echo/add \u7B49\u5DE5\u5177\uFF0C\u9002\u5408\u9A8C\u8BC1\u94FE\u8DEF",
    json: '{\n  "mcpServers": {\n    "everything": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-everything"]\n    }\n  }\n}'
  },
  {
    id: "filesystem",
    label: "Filesystem",
    description: "\u53D7\u9650\u76EE\u5F55\u7684\u6587\u4EF6\u8BFB\u5199\u4E0E\u641C\u7D22",
    json: '{\n  "mcpServers": {\n    "filesystem": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]\n    }\n  }\n}'
  },
  {
    id: "fetch",
    label: "Fetch",
    description: "\u7F51\u9875\u6293\u53D6\u8F6C Markdown",
    json: '{\n  "mcpServers": {\n    "fetch": {\n      "command": "uvx",\n      "args": ["mcp-server-fetch"]\n    }\n  }\n}'
  },
  {
    id: "memory",
    label: "Memory",
    description: "\u77E5\u8BC6\u56FE\u8C31\u5F0F\u6301\u4E45\u8BB0\u5FC6",
    json: '{\n  "mcpServers": {\n    "memory": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-memory"]\n    }\n  }\n}'
  },
  {
    id: "sequential-thinking",
    label: "Seq Thinking",
    description: "\u7ED3\u6784\u5316\u5206\u6B65\u63A8\u7406\u5DE5\u5177",
    json: '{\n  "mcpServers": {\n    "seq-thinking": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]\n    }\n  }\n}'
  },
  {
    id: "puppeteer",
    label: "Puppeteer",
    description: "\u6D4F\u89C8\u5668\u81EA\u52A8\u5316\uFF08\u5BFC\u822A/\u622A\u56FE/\u70B9\u51FB\uFF09",
    json: '{\n  "mcpServers": {\n    "puppeteer": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-puppeteer"]\n    }\n  }\n}'
  },
  {
    id: "github",
    label: "GitHub",
    description: "\u4ED3\u5E93/Issue/PR \u64CD\u4F5C\uFF0C\u9700\u8981 token",
    json: '{\n  "mcpServers": {\n    "github": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-github"],\n      "env": { "GITHUB_TOKEN": "ghp_xxx" }\n    }\n  }\n}'
  },
  {
    id: "chrome-devtools",
    label: "Chrome DevTools",
    description: "Chrome DevTools MCP\uFF1A\u9875\u9762\u5FEB\u7167\u3001\u70B9\u51FB\u3001\u586B\u8868\u3001\u7F51\u7EDC\u4E0E\u63A7\u5236\u53F0\uFF08npx \u62C9\u8D77\uFF0C\u53EF\u6539\u672C\u5730\u8DEF\u5F84\uFF09",
    json: '{\n  "mcpServers": {\n    "chrome-devtools": {\n      "command": "npx",\n      "args": ["-y", "chrome-devtools-mcp@latest"]\n    }\n  }\n}'
  },
  {
    id: "http-example",
    label: "HTTP \u793A\u4F8B",
    description: "streamable-http \u4F20\u8F93\u7684\u6A21\u677F",
    json: '{\n  "mcpServers": {\n    "remote": {\n      "type": "http",\n      "url": "http://localhost:3000/mcp",\n      "headers": { "Authorization": "Bearer token" }\n    }\n  }\n}'
  }
];

// src/client/McpStudioPage.tsx
var import_jsx_runtime3 = require("react/jsx-runtime");
var STATUS_POLL_MS = 3e3;
var FILTER_CLASS = {
  all: "",
  connected: "dsh-mcs-state--ok",
  down: "dsh-mcs-state--busy",
  disabled: "dsh-mcs-state--off"
};
function matchesStatusFilter(state, filter) {
  if (filter === "all") return true;
  if (filter === "connected") return state === "connected";
  if (filter === "disabled") return state === "disabled";
  return state === "mounting" || state === "unreachable" || state === "error";
}
function createStudioPage(face, t, pollStatus, diagnose, clearExecutions) {
  return function McpStudioPage() {
    const state = useStoreState(face.hooks.studio);
    const [openIds, setOpenIds] = (0, import_react3.useState)(() => /* @__PURE__ */ new Set());
    const [live, setLive] = (0, import_react3.useState)(void 0);
    const [pasteOpen, setPasteOpen] = (0, import_react3.useState)(false);
    const [pasteText, setPasteText] = (0, import_react3.useState)("");
    const [templateFilled, setTemplateFilled] = (0, import_react3.useState)(false);
    const [pasteNote, setPasteNote] = (0, import_react3.useState)(void 0);
    const [filterText, setFilterText] = (0, import_react3.useState)("");
    const [statusFilter, setStatusFilter] = (0, import_react3.useState)("all");
    const [compact, setCompact] = (0, import_react3.useState)(false);
    const [draggingId, setDraggingId] = (0, import_react3.useState)(void 0);
    const [overId, setOverId] = (0, import_react3.useState)(void 0);
    const [execPage, setExecPage] = (0, import_react3.useState)(0);
    const [execServerFilter, setExecServerFilter] = (0, import_react3.useState)("");
    const [confirmClear, setConfirmClear] = (0, import_react3.useState)(false);
    (0, import_react3.useEffect)(() => {
      let alive = true;
      const tick = async () => {
        const result = await pollStatus();
        if (alive && !("error" in result)) setLive(result);
      };
      void tick();
      const timer = setInterval(() => {
        void tick();
      }, STATUS_POLL_MS);
      return () => {
        alive = false;
        clearInterval(timer);
      };
    }, [pollStatus]);
    const toggle = (0, import_react3.useCallback)((id) => {
      setOpenIds((current) => {
        const next = new Set(current);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    }, []);
    const addServer = (0, import_react3.useCallback)(() => {
      face.addServer();
    }, [face]);
    const openDrawer = (0, import_react3.useCallback)((prefill) => {
      if (prefill !== void 0) setPasteText(prefill);
      else if (!templateFilled && pasteText.trim() === "") {
        setPasteText(MCP_JSON_TEMPLATE);
        setTemplateFilled(true);
      }
      setPasteOpen(true);
    }, [pasteText, templateFilled]);
    const runFormat = (0, import_react3.useCallback)(() => {
      const result = formatMcpJson(pasteText);
      if ("error" in result) {
        setPasteNote({ kind: "err", text: result.error });
        return;
      }
      setPasteText(result.text);
      setPasteNote(void 0);
    }, [pasteText]);
    const runJsonImport = (0, import_react3.useCallback)(() => {
      const result = face.importMcpJson(pasteText);
      if ("error" in result) {
        setPasteNote({ kind: "err", text: result.error });
        return;
      }
      setPasteOpen(false);
      setPasteText("");
      setPasteNote({ kind: "ok", text: `${t("importDone")} ${result.servers}${result.warnings.length > 0 ? ` \xB7 ${result.warnings.join("\uFF1B")}` : ""}` });
    }, [face, pasteText, t]);
    const copyAll = (0, import_react3.useCallback)(() => {
      const json = serversToMcpJson(state.view.servers);
      void navigator.clipboard?.writeText(json).then(
        () => setPasteNote({ kind: "ok", text: t("copiedAll") }),
        () => openDrawer(json)
      );
    }, [state.view.servers, t, openDrawer]);
    const liveById = (0, import_react3.useMemo)(() => new Map((live?.servers ?? []).map((server) => [server.id, server])), [live]);
    const visibleServers = (0, import_react3.useMemo)(() => {
      const needle = filterText.trim().toLowerCase();
      return state.view.servers.filter((server) => {
        if (statusFilter !== "all") {
          const serverState = liveById.get(server.id)?.state ?? (server.enabled ? "mounting" : "disabled");
          if (!matchesStatusFilter(serverState, statusFilter)) return false;
        }
        if (needle === "") return true;
        return server.name.toLowerCase().includes(needle) || server.command.toLowerCase().includes(needle) || server.url.toLowerCase().includes(needle) || server.argsLine.toLowerCase().includes(needle);
      });
    }, [state.view.servers, filterText, statusFilter, liveById]);
    const formatTime = (at) => {
      const date = new Date(at);
      const pad = (value) => String(value).padStart(2, "0");
      return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
    };
    if (state.status === "loading") {
      return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-mcs-spin" }),
        " ",
        t("loading")
      ] });
    }
    if (state.status !== "ready") {
      return /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-mcs", children: t("readOnly") });
    }
    const canSave = state.dirty && !state.saving && state.errors.length === 0 && state.writable;
    return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: compact ? "dsh-mcs dsh-mcs--compact" : "dsh-mcs", children: [
      /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-head", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("h2", { className: "dsh-mcs-title", children: t("title") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("p", { className: "dsh-mcs-sub", children: t("subtitle") })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-toolbar", children: [
          state.dirty && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-mcs-dirty", children: t("unsaved") }),
          state.failed && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-mcs-failed", children: t("saveFailed") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: () => setCompact((value) => !value), children: compact ? t("comfortable") : t("compact") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: () => {
            if (pasteOpen) setPasteOpen(false);
            else openDrawer();
          }, children: t("pasteJson") }),
          state.view.servers.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: copyAll, children: t("copyJson") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--primary", disabled: state.saving, onClick: addServer, children: t("addServer") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", disabled: !state.dirty || state.saving, onClick: () => face.discard(), children: t("discard") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--primary", disabled: !canSave, onClick: () => void face.save(), children: t("save") })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-stats", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-stat", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { children: t("statTotal") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("strong", { children: live?.summary.total ?? state.view.servers.length })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-stat", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { children: t("statEnabled") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("strong", { children: live?.summary.enabled ?? state.view.servers.filter((server) => server.enabled).length })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-stat dsh-mcs-stat--ok", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { children: t("statConnected") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("strong", { children: live?.summary.connected ?? 0 })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-stat dsh-mcs-stat--accent", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { children: t("statTools") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("strong", { children: live?.summary.tools ?? 0 })
        ] })
      ] }),
      pasteOpen && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-mcs-drawer", children: /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-drawer-inner", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("small", { style: { color: "var(--dsw-alias-label-secondary)" }, children: t("pasteJsonHint") }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-mcs-presets", children: SERVER_PRESETS.map((preset) => /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
          "button",
          {
            type: "button",
            className: "dsh-mcs-preset",
            title: preset.description,
            onClick: () => {
              setPasteText(preset.json);
              setTemplateFilled(true);
              setPasteNote(void 0);
            },
            children: preset.label
          },
          preset.id
        )) }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
          "textarea",
          {
            className: "dsh-mcs-json",
            rows: 7,
            spellCheck: false,
            placeholder: t("pasteJsonPlaceholder"),
            value: pasteText,
            onChange: (event) => setPasteText(event.target.value)
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-toolbar", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: () => {
            setPasteText(MCP_JSON_TEMPLATE);
            setTemplateFilled(true);
            setPasteNote(void 0);
          }, children: t("fillTemplate") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", disabled: pasteText.trim() === "", onClick: runFormat, children: t("formatJson") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { style: { flex: 1 } }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--primary", disabled: pasteText.trim() === "", onClick: runJsonImport, children: t("importJson") })
        ] })
      ] }) }),
      pasteNote !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: pasteNote.kind === "ok" ? "dsh-mcs-sub" : "dsh-mcs-errors", style: pasteNote.kind === "ok" ? void 0 : { padding: "6px 10px" }, children: pasteNote.text }),
      !state.writable && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("p", { className: "dsh-mcs-sub", children: t("readOnly") }),
      state.errors.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-errors", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("strong", { children: t("errorsHeader") }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("ul", { children: state.errors.map((error, index) => /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("li", { children: error }, index)) })
      ] }),
      state.view.servers.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-filterbar", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
          "input",
          {
            className: "dsh-mcs-search",
            style: { maxWidth: 260 },
            placeholder: t("filterServers"),
            value: filterText,
            onChange: (event) => setFilterText(event.target.value)
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-mcs-seg", children: ["all", "connected", "down", "disabled"].map((filter) => /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
          "button",
          {
            type: "button",
            className: statusFilter === filter ? "is-on" : void 0,
            "aria-pressed": statusFilter === filter,
            onClick: () => setStatusFilter(filter),
            children: /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: FILTER_CLASS[filter], children: t(`filter_${filter}`) })
          },
          filter
        )) }),
        visibleServers.length !== state.view.servers.length && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("span", { className: "dsh-mcs-sub", style: { margin: 0 }, children: [
          visibleServers.length,
          " / ",
          state.view.servers.length
        ] })
      ] }),
      state.view.servers.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-empty", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("p", { children: t("empty") }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-toolbar", style: { justifyContent: "center" }, children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--primary", disabled: state.saving, onClick: addServer, children: t("addServer") }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", onClick: () => openDrawer(), children: t("pasteJson") })
        ] })
      ] }) : visibleServers.map((server) => /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
        "div",
        {
          draggable: !openIds.has(server.id),
          onDragStart: (event) => {
            setDraggingId(server.id);
            event.dataTransfer.effectAllowed = "move";
            event.dataTransfer.setData("text/plain", server.id);
          },
          onDragEnd: () => {
            setDraggingId(void 0);
            setOverId(void 0);
          },
          onDragOver: (event) => {
            if (draggingId === void 0 || draggingId === server.id) return;
            event.preventDefault();
            event.dataTransfer.dropEffect = "move";
            setOverId(server.id);
          },
          onDragLeave: () => setOverId((current) => current === server.id ? void 0 : current),
          onDrop: (event) => {
            event.preventDefault();
            const dragged = draggingId ?? event.dataTransfer.getData("text/plain");
            if (dragged !== "" && dragged !== server.id) face.moveServer(dragged, server.id);
            setDraggingId(void 0);
            setOverId(void 0);
          },
          className: draggingId === server.id ? "dsh-mcs-drag" : void 0,
          "data-droptarget": overId === server.id ? "1" : void 0,
          children: /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
            ServerCard,
            {
              server,
              live: liveById.get(server.id),
              open: openIds.has(server.id),
              onToggle: () => toggle(server.id),
              t,
              disabled: state.saving,
              onUpdate: (next) => face.updateServerDraft(next),
              onRemove: () => face.removeServer(server.id),
              diagnose
            }
          )
        },
        server.id
      )),
      (live?.executions?.length ?? 0) > 0 && (() => {
        const records = (live.executions ?? []).filter((record) => execServerFilter === "" || record.server === execServerFilter);
        const capacity = live?.execCapacity ?? 200;
        const pageSize = 20;
        const pageCount = Math.max(1, Math.ceil(records.length / pageSize));
        const page = Math.min(execPage, pageCount - 1);
        const rows = records.slice(page * pageSize, page * pageSize + pageSize);
        const servers = [...new Set((live.executions ?? []).map((record) => record.server))].sort();
        return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-exec", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-exec-head", children: [
            /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("h4", { className: "dsh-mcs-exec-title", children: [
              t("execTitle"),
              " (",
              records.length,
              "/",
              capacity,
              ")"
            ] }),
            servers.length > 1 && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)(
              "select",
              {
                className: "dsh-mcs-search",
                style: { maxWidth: 160 },
                value: execServerFilter,
                onChange: (event) => {
                  setExecServerFilter(event.target.value);
                  setExecPage(0);
                },
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("option", { value: "", children: t("execAllServers") }),
                  servers.map((server) => /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("option", { value: server, children: server }, server))
                ]
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { style: { flex: 1 } }),
            clearExecutions !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
              "button",
              {
                type: "button",
                className: confirmClear ? "dsh-mcs-btn dsh-mcs-btn--danger2" : "dsh-mcs-btn dsh-mcs-btn--ghost",
                onClick: () => {
                  if (!confirmClear) {
                    setConfirmClear(true);
                    setTimeout(() => setConfirmClear(false), 3e3);
                    return;
                  }
                  setConfirmClear(false);
                  void clearExecutions().then(() => setExecPage(0));
                },
                children: confirmClear ? t("execConfirmClear") : t("execClear")
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("table", { className: "dsh-mcs-exectable", children: [
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("tr", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("th", { children: t("execTime") }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("th", { children: t("execServer") }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("th", { children: t("execTool") }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("th", { children: t("execDuration") }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("th", { children: t("execStatus") })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("tbody", { children: rows.map((record, index) => /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("tr", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("td", { children: formatTime(record.at) }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("td", { children: record.server }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("code", { children: record.tool }) }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("td", { children: [
                record.durationMs,
                " ms"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("td", { children: record.ok ? /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-mcs-exec-ok", children: t("execOk") }) : /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-mcs-exec-err", title: record.error ?? "", children: t("execFailed") }) })
            ] }, index)) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-exec-foot", children: [
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("small", { className: "dsh-mcs-sub", style: { margin: 0 }, children: t("execMemoryHint", { capacity }) }),
            pageCount > 1 && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-mcs-pager", children: [
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", disabled: page === 0, onClick: () => setExecPage(page - 1), children: "\u2039" }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("span", { children: [
                page + 1,
                " / ",
                pageCount
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("button", { type: "button", className: "dsh-mcs-btn dsh-mcs-btn--ghost", disabled: page >= pageCount - 1, onClick: () => setExecPage(page + 1), children: "\u203A" })
            ] })
          ] })
        ] });
      })()
    ] });
  };
}

// src/client/store.ts
function createStore(initial) {
  let snapshot = initial;
  const listeners = /* @__PURE__ */ new Set();
  return {
    getSnapshot: () => snapshot,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    set: (next) => {
      if (Object.is(snapshot, next)) return;
      snapshot = next;
      for (const listener of [...listeners]) {
        try {
          listener();
        } catch (error) {
          console.warn("[dsh-mcp-studio] listener failed", error);
        }
      }
    }
  };
}

// src/client/controller.ts
var NAME_RE = /^[A-Za-z0-9_-]{1,32}$/;
function pairsToDict(pairs) {
  const dict = {};
  for (const pair of pairs) {
    const key = pair.key.trim();
    if (key !== "") dict[key] = pair.value;
  }
  return dict;
}
function dictToPairs(dict) {
  if (typeof dict !== "object" || dict === null || Array.isArray(dict)) return [];
  return Object.entries(dict).map(([key, value]) => ({
    key,
    value: typeof value === "string" ? value : ""
  }));
}
function serverToDraft(raw) {
  const server = typeof raw === "object" && raw !== null ? raw : {};
  return {
    id: typeof server.id === "string" ? server.id : "",
    enabled: server.enabled !== false,
    name: typeof server.name === "string" ? server.name : "",
    transport: server.transport === "streamable-http" ? "streamable-http" : "stdio",
    command: typeof server.command === "string" ? server.command : "",
    argsLine: typeof server.argsLine === "string" ? server.argsLine : "",
    env: dictToPairs(server.env),
    cwd: typeof server.cwd === "string" ? server.cwd : "",
    url: typeof server.url === "string" ? server.url : "",
    headers: dictToPairs(server.headers),
    toolCallTimeoutMs: typeof server.toolCallTimeoutMs === "number" ? server.toolCallTimeoutMs : 6e4,
    failOnStartupError: server.failOnStartupError === true
  };
}
function sectionToDraft(section) {
  const raw = typeof section === "object" && section !== null ? section : {};
  const servers = Array.isArray(raw.servers) ? raw.servers.map(serverToDraft) : [];
  return { servers };
}
function draftToSection(draft) {
  return {
    servers: draft.servers.map((server) => ({
      id: server.id,
      enabled: server.enabled,
      name: server.name,
      transport: server.transport,
      command: server.command,
      argsLine: server.argsLine,
      env: pairsToDict(server.env),
      cwd: server.cwd,
      url: server.url,
      headers: pairsToDict(server.headers),
      toolCallTimeoutMs: server.toolCallTimeoutMs,
      failOnStartupError: server.failOnStartupError
    }))
  };
}
function validateDraft(section) {
  const errors = [];
  const names = /* @__PURE__ */ new Set();
  for (const server of section.servers) {
    if (server.name !== "" && !NAME_RE.test(server.name)) {
      errors.push(`server name "${server.name}" must match [A-Za-z0-9_-]{1,32}`);
    }
    if (!server.enabled) continue;
    if (server.name === "") errors.push("an enabled server has no name");
    else if (names.has(server.name)) errors.push(`two enabled servers share the name "${server.name}"`);
    if (server.name !== "") names.add(server.name);
    if (server.transport === "stdio") {
      if (server.command.trim() === "") errors.push(`stdio server "${server.name || "(unnamed)"}" needs a command`);
    } else {
      if (server.url.trim() === "") {
        errors.push(`server "${server.name || "(unnamed)"}" needs a url`);
      } else {
        let parsed;
        try {
          parsed = new URL(server.url);
        } catch {
          parsed = void 0;
        }
        if (parsed === void 0) errors.push(`server "${server.name}" url is not valid`);
        else if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          errors.push(`server "${server.name}" url must use http or https`);
        }
      }
    }
  }
  return errors;
}
var StudioController = class {
  constructor(scope) {
    this.scope = scope;
    this.store = createStore(this.projection());
    this.scope.subscribe(() => this.publish());
  }
  store;
  staged;
  saving = false;
  failed = false;
  getStore() {
    return this.store;
  }
  currentDraft() {
    if (this.staged !== void 0) return this.staged;
    return sectionToDraft(this.scope.getSnapshot().value);
  }
  projection() {
    const snapshot = this.scope.getSnapshot();
    const staged = this.staged;
    const view = staged !== void 0 ? staged : this.currentDraft();
    const errors = staged !== void 0 ? validateDraft(staged) : [];
    const dirty = staged !== void 0 && JSON.stringify(draftToSection(staged)) !== JSON.stringify(draftToSection(sectionToDraft(snapshot.value)));
    return {
      status: snapshot.status,
      writable: snapshot.writable,
      view,
      dirty,
      saving: this.saving,
      failed: this.failed,
      errors
    };
  }
  publish() {
    this.store.set(this.projection());
  }
  /** Adds a blank row and returns its id (the page expands only these). */
  addServer() {
    const base = this.currentDraft();
    const used = new Set(base.servers.map((server) => server.id));
    const names = new Set(base.servers.map((server) => server.name));
    let id = `srv-${Date.now().toString(36)}`;
    while (used.has(id)) id = `${id}x`;
    let number = base.servers.length + 1;
    let name2 = `server-${number}`;
    while (names.has(name2)) {
      number += 1;
      name2 = `server-${number}`;
    }
    this.staged = {
      ...base,
      servers: [...base.servers, {
        id,
        enabled: true,
        name: name2,
        transport: "stdio",
        command: "",
        argsLine: "",
        env: [],
        cwd: "",
        url: "",
        headers: [],
        toolCallTimeoutMs: 6e4,
        failOnStartupError: false
      }]
    };
    this.failed = false;
    this.publish();
    return id;
  }
  updateServerDraft(next) {
    const base = this.currentDraft();
    this.staged = {
      ...base,
      servers: base.servers.map((server) => server.id === next.id ? next : server)
    };
    this.failed = false;
    this.publish();
  }
  removeServer(id) {
    const base = this.currentDraft();
    this.staged = { ...base, servers: base.servers.filter((server) => server.id !== id) };
    this.failed = false;
    this.publish();
  }
  /** Parse pasted MCP-client JSON and stage every server entry as a new row. */
  importMcpJson(text) {
    const base = this.currentDraft();
    const result = parseMcpJson(text, base.servers.map((server) => server.name));
    if ("error" in result) return { error: result.error };
    const used = new Set(base.servers.map((server) => server.id));
    const rows = result.servers.map((server, index) => {
      let id = `srv-${Date.now().toString(36)}-${index}`;
      while (used.has(id)) id = `${id}x`;
      return { ...server, id };
    });
    this.staged = { ...base, servers: [...base.servers, ...rows] };
    this.failed = false;
    this.publish();
    return { servers: rows.length, warnings: result.warnings };
  }
  /** Reorder: move `id` directly before `targetId` in the staged draft. */
  moveServer(id, targetId) {
    if (id === targetId) return;
    const base = this.currentDraft();
    const from = base.servers.findIndex((server) => server.id === id);
    const to = base.servers.findIndex((server) => server.id === targetId);
    if (from < 0 || to < 0) return;
    const servers = [...base.servers];
    const [moved] = servers.splice(from, 1);
    servers.splice(to, 0, moved);
    this.staged = { ...base, servers };
    this.failed = false;
    this.publish();
  }
  async save() {
    const staged = this.staged;
    const snapshot = this.scope.getSnapshot();
    if (staged === void 0 || this.saving || snapshot.status !== "ready") return;
    if (validateDraft(staged).length > 0) return;
    this.saving = true;
    this.failed = false;
    this.publish();
    try {
      const wire = draftToSection(staged);
      const stored = draftToSection(sectionToDraft(snapshot.value));
      if (JSON.stringify(wire.servers) !== JSON.stringify(stored.servers)) {
        await this.scope.set("servers", wire.servers);
      }
      this.staged = void 0;
    } catch (error) {
      console.warn("[dsh-mcp-studio] save failed", error);
      this.failed = true;
    } finally {
      this.saving = false;
      this.publish();
    }
  }
  discard() {
    this.staged = void 0;
    this.failed = false;
    this.publish();
  }
  inject() {
    return {
      hooks: { studio: this.store },
      addServer: () => this.addServer(),
      updateServerDraft: (next) => this.updateServerDraft(next),
      removeServer: (id) => this.removeServer(id),
      importMcpJson: (text) => this.importMcpJson(text),
      moveServer: (id, targetId) => this.moveServer(id, targetId),
      save: () => this.save(),
      discard: () => this.discard()
    };
  }
};

// src/settings-rpc.ts
var STUDIO_CHANNEL = "/dsh-mcp-studio";

// src/client/studio-scope.ts
var StudioScope = class {
  constructor(call) {
    this.call = call;
    void this.load();
  }
  snapshot = { status: "loading", value: void 0, base: void 0, user: void 0, revision: void 0, writable: false, mode: "host" };
  listeners = /* @__PURE__ */ new Set();
  tail = Promise.resolve();
  getSnapshot = () => this.snapshot;
  subscribe = (listener) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  set(field, value) {
    return this.write({ op: "set", path: [field], value });
  }
  unset(field) {
    return this.write({ op: "unset", path: [field] });
  }
  async status() {
    const response = await this.call("status", {});
    if (!response.ok) return { error: response.error.message };
    const value = response.value;
    if (!Array.isArray(value.servers) || typeof value.summary !== "object" || value.summary === null) {
      return { error: "host returned no status payload" };
    }
    return value;
  }
  async clearExecutions() {
    const response = await this.call("executions/clear", {});
    if (!response.ok) return { error: response.error.message };
    return { cleared: true };
  }
  async diagnose(id) {
    const response = await this.call("diagnose", { id });
    if (!response.ok) return { error: response.error.message };
    return response.value;
  }
  async load() {
    const response = await this.call("settings/get", {});
    if (!response.ok) {
      this.publish({ ...this.snapshot, status: "unavailable" });
      return;
    }
    const view = typeof response.value === "object" && response.value !== null ? response.value : {};
    this.publish({
      status: "ready",
      value: view.value,
      base: view.base,
      user: view.user,
      revision: typeof view.revision === "number" ? view.revision : void 0,
      writable: view.writable === true,
      mode: "host"
    });
  }
  write(op) {
    const task = this.tail.then(async () => {
      const response = await this.call("settings/mutate", {
        ops: [op],
        ...this.snapshot.revision === void 0 ? {} : { expectedRevision: this.snapshot.revision }
      });
      if (!response.ok) throw new Error(response.error.message);
      const view = typeof response.value === "object" && response.value !== null ? response.value : {};
      this.publish({
        status: "ready",
        value: view.value,
        base: view.base,
        user: view.user,
        revision: typeof view.revision === "number" ? view.revision : void 0,
        writable: view.writable === true,
        mode: "host"
      });
    });
    this.tail = task.catch(() => {
    });
    return task;
  }
  publish(snapshot) {
    this.snapshot = snapshot;
    for (const listener of this.listeners) listener();
  }
};
function createStudioScope(connection) {
  return new StudioScope((endpoint, payload) => connection.rpc.call(STUDIO_CHANNEL, endpoint, payload));
}

// src/client/locales.ts
var NS = "mcp-studio";
var en = {
  nav: "MCP Studio",
  title: "MCP Studio",
  subtitle: "Every enabled server mounts live and exposes its tools to the model as mcp__<name>__<tool>. Saves apply immediately \u2014 no restart needed.",
  save: "Save",
  discard: "Discard",
  unsaved: "Unsaved changes",
  readOnly: "The settings document is read-only.",
  saveFailed: "The last save was rejected. Review the values and save again.",
  errorsHeader: "Fix these before saving:",
  loading: "Loading\u2026",
  statTotal: "Servers",
  statEnabled: "Enabled",
  statConnected: "Connected",
  statTools: "Tools",
  addServer: "Add server",
  removeServer: "Remove server",
  serverEnabled: "Enabled",
  unnamedServer: "(unnamed server)",
  serverName: "Server name",
  serverNameHint: 'Tool namespace; letters, digits, "_" and "-" only. Changing it renames every tool.',
  transport: "Transport",
  command: "Command",
  commandHint: "Executable to spawn, e.g. npx or an absolute path.",
  argsLine: "Arguments",
  argsLineHint: "One line; quotes are honored, e.g. -y @modelcontextprotocol/server-github.",
  cwd: "Working directory",
  cwdHint: "Empty inherits the Harness working directory.",
  url: "URL",
  urlHint: "MCP endpoint, e.g. http://localhost:3000/mcp.",
  env: "Environment",
  envHint: "Extra variables merged over the child environment. Values are stored in your local settings file.",
  headers: "Headers",
  headersHint: "Extra request headers, e.g. Authorization. Values are stored in your local settings file.",
  addPair: "Add entry",
  removePair: "Remove",
  pairValuePlaceholder: "value",
  toolCallTimeoutMs: "Tool-call timeout (ms)",
  failOnStartupError: "Fail mount on startup error",
  failOnStartupErrorHint: "Otherwise an unreachable server simply contributes no tools.",
  empty: "No MCP servers configured yet. Add one, or paste an existing config.",
  pasteJson: "Paste JSON",
  pasteJsonHint: "Accepts Claude Desktop / VS Code / Cline / bare-map MCP config JSON; every entry becomes one row below.",
  pasteJsonPlaceholder: '{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "..."}}}}',
  importJson: "Import",
  importDone: "imported",
  toolsTitle: "Tools",
  toolsSearchPlaceholder: "Filter tools\u2026",
  toolsEmpty: "No tool matches this filter.",
  toolsWaiting: "Tools appear here once the server connects.",
  stateConnected: "connected",
  stateMounting: "starting",
  stateUnreachable: "not connected",
  stateError: "failed",
  stateDisabled: "disabled",
  toolsUnit: "tools",
  toolsPreviewHint: "View tools",
  fillTemplate: "Template",
  formatJson: "Format",
  copyJson: "Copy JSON",
  copyThisServer: "Copy this server as JSON",
  copied: "Copied",
  copiedAll: "Configuration copied as mcpServers JSON",
  filterServers: "Filter servers by name, command, or url\u2026",
  filter_all: "All",
  filter_connected: "Connected",
  filter_down: "Not connected",
  filter_disabled: "Disabled",
  transportHint: "Type stdio or http.",
  transportInvalid: "Enter stdio or http.",
  compact: "Compact",
  comfortable: "Comfortable",
  execTitle: "Recent tool calls",
  execTime: "Time",
  execServer: "Server",
  execTool: "Tool",
  execDuration: "Duration",
  execStatus: "Status",
  execOk: "ok",
  execFailed: "failed",
  testConnection: "Test connection",
  diagElapsed: "Handshake",
  diagProtocol: "Protocol",
  diagServer: "Server",
  diagTools: "Tools",
  execAllServers: "All servers",
  execClear: "Clear log",
  execConfirmClear: "Confirm clear?",
  execMemoryHint: "In-memory log: up to {capacity} records, cleared on DSH restart."
};
var zh = {
  nav: "MCP \u5DE5\u4F5C\u53F0",
  title: "MCP \u5DE5\u4F5C\u53F0",
  subtitle: "\u6BCF\u4E2A\u542F\u7528\u7684\u670D\u52A1\u5668\u5B9E\u65F6\u6302\u8F7D\uFF0C\u5E76\u4EE5 mcp__<\u540D\u79F0>__<\u5DE5\u5177> \u7684\u5F62\u5F0F\u5411\u6A21\u578B\u66B4\u9732\u5DE5\u5177\u3002\u4FDD\u5B58\u540E\u5373\u65F6\u751F\u6548\uFF0C\u65E0\u9700\u91CD\u542F\u3002",
  save: "\u4FDD\u5B58",
  discard: "\u653E\u5F03\u4FEE\u6539",
  unsaved: "\u6709\u672A\u4FDD\u5B58\u7684\u4FEE\u6539",
  readOnly: "\u8BBE\u7F6E\u6587\u6863\u5F53\u524D\u53EA\u8BFB\u3002",
  saveFailed: "\u4E0A\u6B21\u4FDD\u5B58\u88AB\u62D2\u7EDD\uFF0C\u8BF7\u68C0\u67E5\u914D\u7F6E\u540E\u91CD\u8BD5\u3002",
  errorsHeader: "\u4FDD\u5B58\u524D\u8BF7\u5148\u4FEE\u590D\uFF1A",
  loading: "\u52A0\u8F7D\u4E2D\u2026",
  statTotal: "\u670D\u52A1\u5668",
  statEnabled: "\u5DF2\u542F\u7528",
  statConnected: "\u5DF2\u8FDE\u63A5",
  statTools: "\u5DE5\u5177",
  addServer: "\u6DFB\u52A0\u670D\u52A1\u5668",
  removeServer: "\u5220\u9664\u670D\u52A1\u5668",
  serverEnabled: "\u542F\u7528",
  unnamedServer: "\uFF08\u672A\u547D\u540D\u670D\u52A1\u5668\uFF09",
  serverName: "\u670D\u52A1\u5668\u540D\u79F0",
  serverNameHint: '\u5DE5\u5177\u547D\u540D\u7A7A\u95F4\uFF0C\u4EC5\u9650\u5B57\u6BCD\u3001\u6570\u5B57\u3001"_" \u548C "-"\u3002\u4FEE\u6539\u5B83\u4F1A\u91CD\u547D\u540D\u5168\u90E8\u5DE5\u5177\u3002',
  transport: "\u4F20\u8F93\u65B9\u5F0F",
  command: "\u542F\u52A8\u547D\u4EE4",
  commandHint: "\u8981\u542F\u52A8\u7684\u53EF\u6267\u884C\u6587\u4EF6\uFF0C\u4F8B\u5982 npx \u6216\u7EDD\u5BF9\u8DEF\u5F84\u3002",
  argsLine: "\u53C2\u6570",
  argsLineHint: "\u4E00\u884C\u5199\u5B8C\uFF0C\u652F\u6301\u5F15\u53F7\uFF0C\u4F8B\u5982 -y @modelcontextprotocol/server-github\u3002",
  cwd: "\u5DE5\u4F5C\u76EE\u5F55",
  cwdHint: "\u7559\u7A7A\u5219\u7EE7\u627F Harness \u7684\u5DE5\u4F5C\u76EE\u5F55\u3002",
  url: "URL",
  urlHint: "MCP \u7AEF\u70B9\uFF0C\u4F8B\u5982 http://localhost:3000/mcp\u3002",
  env: "\u73AF\u5883\u53D8\u91CF",
  envHint: "\u989D\u5916\u6CE8\u5165\u5B50\u8FDB\u7A0B\u7684\u73AF\u5883\u53D8\u91CF\u3002\u503C\u660E\u6587\u4FDD\u5B58\u5728\u672C\u5730\u8BBE\u7F6E\u6587\u4EF6\u4E2D\u3002",
  headers: "\u8BF7\u6C42\u5934",
  headersHint: "\u989D\u5916\u7684\u8BF7\u6C42\u5934\uFF0C\u4F8B\u5982 Authorization\u3002\u503C\u660E\u6587\u4FDD\u5B58\u5728\u672C\u5730\u8BBE\u7F6E\u6587\u4EF6\u4E2D\u3002",
  addPair: "\u6DFB\u52A0\u4E00\u9879",
  removePair: "\u79FB\u9664",
  pairValuePlaceholder: "\u503C",
  toolCallTimeoutMs: "\u5355\u6B21\u5DE5\u5177\u8C03\u7528\u8D85\u65F6\uFF08\u6BEB\u79D2\uFF09",
  failOnStartupError: "\u542F\u52A8\u5931\u8D25\u5373\u62A5\u9519",
  failOnStartupErrorHint: "\u5173\u95ED\u65F6\uFF0C\u8FDE\u4E0D\u4E0A\u7684\u670D\u52A1\u5668\u53EA\u662F\u4E0D\u8D21\u732E\u4EFB\u4F55\u5DE5\u5177\u3002",
  empty: "\u8FD8\u6CA1\u6709\u914D\u7F6E MCP \u670D\u52A1\u5668\u3002\u6DFB\u52A0\u4E00\u4E2A\uFF0C\u6216\u76F4\u63A5\u7C98\u8D34\u73B0\u6210\u914D\u7F6E\u3002",
  pasteJson: "\u7C98\u8D34 JSON",
  pasteJsonHint: "\u652F\u6301 Claude Desktop / VS Code / Cline / \u88F8\u6620\u5C04\u7B49\u5E38\u89C1 MCP \u914D\u7F6E\u683C\u5F0F\uFF0C\u6BCF\u4E00\u6761\u89E3\u6790\u4E3A\u4E0B\u65B9\u4E00\u884C\u3002",
  pasteJsonPlaceholder: '{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "..."}}}}',
  importJson: "\u5BFC\u5165",
  importDone: "\u5DF2\u5BFC\u5165",
  toolsTitle: "\u5DE5\u5177",
  toolsSearchPlaceholder: "\u7B5B\u9009\u5DE5\u5177\u2026",
  toolsEmpty: "\u6CA1\u6709\u5339\u914D\u8BE5\u7B5B\u9009\u7684\u5DE5\u5177\u3002",
  toolsWaiting: "\u670D\u52A1\u5668\u8FDE\u63A5\u540E\uFF0C\u5DE5\u5177\u4F1A\u663E\u793A\u5728\u8FD9\u91CC\u3002",
  stateConnected: "\u5DF2\u8FDE\u63A5",
  stateMounting: "\u542F\u52A8\u4E2D",
  stateUnreachable: "\u672A\u8FDE\u63A5",
  stateError: "\u8FDE\u63A5\u5931\u8D25",
  stateDisabled: "\u5DF2\u7981\u7528",
  toolsUnit: "\u4E2A\u5DE5\u5177",
  toolsPreviewHint: "\u67E5\u770B\u5DE5\u5177",
  fillTemplate: "\u586B\u5165\u6A21\u677F",
  formatJson: "\u683C\u5F0F\u5316",
  copyJson: "\u590D\u5236 JSON",
  copyThisServer: "\u590D\u5236\u6B64\u670D\u52A1\u5668 JSON",
  copied: "\u5DF2\u590D\u5236",
  copiedAll: "\u5DF2\u6309 mcpServers \u683C\u5F0F\u590D\u5236\u5F53\u524D\u914D\u7F6E",
  filterServers: "\u6309\u540D\u79F0\u3001\u547D\u4EE4\u6216 URL \u7B5B\u9009\u670D\u52A1\u5668\u2026",
  filter_all: "\u5168\u90E8",
  filter_connected: "\u5DF2\u8FDE\u63A5",
  filter_down: "\u672A\u8FDE\u63A5",
  filter_disabled: "\u5DF2\u7981\u7528",
  transportHint: "\u8F93\u5165 stdio \u6216 http\u3002",
  transportInvalid: "\u8BF7\u8F93\u5165 stdio \u6216 http\u3002",
  compact: "\u7D27\u51D1",
  comfortable: "\u8212\u9002",
  execTitle: "\u6700\u8FD1\u5DE5\u5177\u8C03\u7528",
  execTime: "\u65F6\u95F4",
  execServer: "\u670D\u52A1\u5668",
  execTool: "\u5DE5\u5177",
  execDuration: "\u8017\u65F6",
  execStatus: "\u72B6\u6001",
  execOk: "\u6210\u529F",
  execFailed: "\u5931\u8D25",
  testConnection: "\u6D4B\u8BD5\u8FDE\u63A5",
  diagElapsed: "\u63E1\u624B\u8017\u65F6",
  diagProtocol: "\u534F\u8BAE\u7248\u672C",
  diagServer: "\u670D\u52A1\u5668\u4FE1\u606F",
  diagTools: "\u5DE5\u5177\u6570",
  execAllServers: "\u5168\u90E8\u670D\u52A1\u5668",
  execClear: "\u6E05\u7A7A\u8BB0\u5F55",
  execConfirmClear: "\u786E\u8BA4\u6E05\u7A7A\uFF1F",
  execMemoryHint: "\u5185\u5B58\u65E5\u5FD7\uFF1A\u6700\u591A\u4FDD\u7559 {capacity} \u6761\uFF0C\u91CD\u542F DSH \u540E\u6E05\u7A7A\u3002"
};

// src/client/styles.ts
var STYLE_ID = "dsh-mcp-studio-styles";
var CSS_TEXT = String.raw`
.dsh-mcs,.dsh-mcs *{box-sizing:border-box}
.dsh-mcs{display:flex;min-height:100%;flex-direction:column;gap:16px;padding:20px clamp(16px,3vw,40px) 44px;color:var(--dsw-alias-label-primary);font-family:var(--dsw-font-family,system-ui);font-size:12px}

/* ---- header ---- */
.dsh-mcs-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap}
.dsh-mcs-title{margin:0;font-size:17px;line-height:26px;font-weight:700;letter-spacing:-.01em}
.dsh-mcs-sub{margin:3px 0 0;color:var(--dsw-alias-label-secondary);font-size:11.5px;line-height:18px;max-width:680px}
.dsh-mcs-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dsh-mcs-btn{display:inline-flex;min-height:30px;align-items:center;justify-content:center;gap:6px;padding:4px 13px;border:1px solid transparent;border-radius:8px;font:600 11px/17px var(--dsw-font-family,system-ui);cursor:pointer;white-space:nowrap;transition:background .15s,border-color .15s,color .15s,opacity .15s}
.dsh-mcs-btn--primary{border-color:var(--dsw-alias-button-info-fill);background:var(--dsw-alias-button-info-fill);color:var(--dsw-alias-label-primary-foreground)}
.dsh-mcs-btn--primary:hover:not(:disabled){filter:brightness(1.08)}
.dsh-mcs-btn--ghost{border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-secondary)}
.dsh-mcs-btn--ghost:hover:not(:disabled){border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 40%,var(--dsw-alias-border-l2));color:var(--dsw-alias-state-business-primary)}
.dsh-mcs-btn--danger{border-color:transparent;background:transparent;color:var(--dsw-alias-label-tertiary)}
.dsh-mcs-btn--danger:hover:not(:disabled){color:var(--dsw-alias-state-error-primary)}
.dsh-mcs-btn:disabled{opacity:.38;cursor:not-allowed}
.dsh-mcs-dirty{color:var(--dsw-alias-state-warn-primary,#b8860b);font-size:11px;line-height:17px}
.dsh-mcs-failed{color:var(--dsw-alias-state-error-primary);font-size:11px;line-height:17px}

/* ---- overview strip ---- */
.dsh-mcs-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.dsh-mcs-stat{position:relative;overflow:hidden;padding:12px 16px;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.dsh-mcs-stat>span{display:block;color:var(--dsw-alias-label-tertiary);font-size:10px;font-weight:650;line-height:15px;text-transform:uppercase;letter-spacing:.07em}
.dsh-mcs-stat>strong{display:block;margin-top:3px;font-size:22px;line-height:30px;font-weight:700;letter-spacing:-.02em;color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums}
.dsh-mcs-stat--accent>strong{color:var(--dsw-alias-state-business-primary)}
.dsh-mcs-stat--ok>strong{color:var(--dsw-alias-state-success-primary)}
.dsh-mcs-stat::after{content:"";position:absolute;top:0;left:0;width:100%;height:2px;background:transparent}
.dsh-mcs-stat--accent::after{background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 55%,transparent)}
.dsh-mcs-stat--ok::after{background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 55%,transparent)}

/* ---- server card ---- */
.dsh-mcs-card{border:1px solid var(--dsw-alias-border-l2);border-radius:13px;background:var(--dsw-alias-bg-layer-1);box-shadow:var(--dsw-shadow-lv1);transition:border-color .15s}
.dsh-mcs-card:hover{border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 24%,var(--dsw-alias-border-l2))}
.dsh-mcs-card.is-open{border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 30%,var(--dsw-alias-border-l2))}
.dsh-mcs-card.is-off{opacity:.72}
.dsh-mcs-card-head{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;user-select:none;border-radius:12px 12px 0 0}
.dsh-mcs-card-head:hover{background:var(--dsw-alias-interactive-bg-hover)}
.dsh-mcs-dot{flex:none;width:9px;height:9px;border-radius:50%;background:var(--dsw-alias-label-tertiary)}
.dsh-mcs-dot--ok{background:var(--dsw-alias-state-success-primary);box-shadow:0 0 0 0 color-mix(in srgb,var(--dsw-alias-state-success-primary) 45%,transparent);animation:dsh-mcs-pulse 2.2s ease-out infinite}
.dsh-mcs-dot--busy{background:var(--dsw-alias-state-warn-primary,#b8860b)}
.dsh-mcs-dot--err{background:var(--dsw-alias-state-error-primary)}
@keyframes dsh-mcs-pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--dsw-alias-state-success-primary) 45%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.dsh-mcs-name{font-size:13px;font-weight:700;line-height:19px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}
.dsh-mcs-chip{flex:none;display:inline-block;padding:1px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;color:var(--dsw-alias-label-tertiary);font-size:9.5px;font-weight:700;line-height:15px;text-transform:uppercase;letter-spacing:.08em}
.dsh-mcs-chip--http{color:var(--dsw-alias-state-business-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 35%,var(--dsw-alias-border-l2))}
.dsh-mcs-cmd{display:flex;min-width:0;flex:1;align-items:center;overflow:hidden;color:var(--dsw-alias-label-tertiary);font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace}
.dsh-mcs-cmd code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}
.dsh-mcs-state{flex:none;font-size:10.5px;font-weight:650;line-height:16px;letter-spacing:.01em}
.dsh-mcs-state--ok{color:var(--dsw-alias-state-success-primary)}
.dsh-mcs-state--busy{color:var(--dsw-alias-state-warn-primary,#b8860b)}
.dsh-mcs-state--err{color:var(--dsw-alias-state-error-primary)}
.dsh-mcs-state--off{color:var(--dsw-alias-label-tertiary)}
.dsh-mcs-toolscount{flex:none;padding:1px 9px;border-radius:999px;background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 12%,transparent);color:var(--dsw-alias-state-business-primary);font-size:10.5px;font-weight:700;line-height:17px;font-variant-numeric:tabular-nums}
.dsh-mcs-switch{flex:none;position:relative;display:inline-block;width:34px;height:19px}
.dsh-mcs-switch input{position:absolute;inset:0;margin:0;opacity:0;cursor:pointer}
.dsh-mcs-switch i{position:absolute;inset:0;border-radius:999px;background:var(--dsw-alias-bg-layer-2,#c8c8c8);border:1px solid var(--dsw-alias-border-l2);transition:background .15s}
.dsh-mcs-switch i::after{content:"";position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:left .15s}
.dsh-mcs-switch input:checked+i{background:var(--dsw-alias-state-business-primary);border-color:transparent}
.dsh-mcs-switch input:checked+i::after{left:17px}
.dsh-mcs-chevron{flex:none;width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:6px;background:transparent;color:var(--dsw-alias-label-tertiary);font-size:10px;cursor:pointer;transition:transform .18s}
.dsh-mcs-card.is-open .dsh-mcs-chevron{transform:rotate(90deg)}
.dsh-mcs-iconbtn{flex:none;display:inline-flex;width:28px;height:28px;align-items:center;justify-content:center;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--dsw-alias-label-tertiary);font-size:15px;line-height:1;cursor:pointer}
.dsh-mcs-iconbtn:hover{background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 10%,transparent);color:var(--dsw-alias-state-error-primary)}
.dsh-mcs-carderr{margin:-4px 16px 12px;border-radius:0 0 10px 10px;padding:8px 12px;border-left:3px solid var(--dsw-alias-state-error-primary);border-radius:6px;background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 7%,transparent);color:var(--dsw-alias-state-error-primary);font:11px/16px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}

/* ---- expanded body: form + tool browser ---- */
.dsh-mcs-body{border-top:1px solid var(--dsw-alias-border-l2);padding:14px 16px 16px;display:flex;flex-direction:column;gap:14px;border-radius:0 0 12px 12px}
.dsh-mcs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px 14px}
.dsh-mcs-field{display:flex;min-width:0;flex-direction:column;gap:5px}
.dsh-mcs-field>span{color:var(--dsw-alias-label-secondary);font-size:10px;font-weight:650;line-height:16px}
.dsh-mcs-field small{color:var(--dsw-alias-label-tertiary);font-size:10px;line-height:15px}
.dsh-mcs-field input,.dsh-mcs-field select,.dsh-mcs-field textarea{width:100%;padding:7px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;outline:none;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:12px/18px var(--dsw-font-family,system-ui)}
.dsh-mcs-field input:focus,.dsh-mcs-field select:focus,.dsh-mcs-field textarea:focus{border-color:var(--dsw-alias-state-business-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--dsw-alias-state-business-primary) 12%,transparent)}
.dsh-mcs-field input::placeholder,.dsh-mcs-field textarea::placeholder{color:var(--dsw-alias-label-tertiary)}
.dsh-mcs-seg{display:inline-flex;padding:3px;gap:2px;border:1px solid var(--dsw-alias-border-l2);border-radius:9px;background:var(--dsw-alias-bg-base)}
.dsh-mcs-seg button{min-height:26px;padding:2px 14px;border:0;border-radius:6px;background:transparent;color:var(--dsw-alias-label-secondary);font:650 11px/17px var(--dsw-font-family,system-ui);cursor:pointer;transition:background .15s,color .15s}
.dsh-mcs-seg button.is-on{background:var(--dsw-alias-bg-layer-2,var(--dsw-alias-interactive-bg-hover));color:var(--dsw-alias-state-business-primary);box-shadow:var(--dsw-shadow-lv1)}
.dsh-mcs-check{display:flex;align-items:center;gap:8px;color:var(--dsw-alias-label-secondary);font-size:11.5px;line-height:17px}
.dsh-mcs-check input{accent-color:var(--dsw-alias-state-business-primary)}
.dsh-mcs-pairs{display:flex;flex-direction:column;gap:6px}
.dsh-mcs-pairrow{display:flex;gap:6px;align-items:center}
.dsh-mcs-pairrow input{flex:1;min-width:0;padding:5px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:7px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:11px/16px ui-monospace,SFMono-Regular,Menlo,monospace}
.dsh-mcs-pairs .dsh-mcs-btn{align-self:flex-start;min-height:26px;font-size:10.5px}

/* ---- tool browser ---- */
.dsh-mcs-tools{display:flex;flex-direction:column;gap:8px;border-top:1px dashed var(--dsw-alias-border-l2);padding-top:12px}
.dsh-mcs-tools-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.dsh-mcs-tools-title{margin:0;font-size:11px;font-weight:700;line-height:17px;color:var(--dsw-alias-label-secondary);text-transform:uppercase;letter-spacing:.06em}
.dsh-mcs-search{flex:1;min-width:160px;max-width:280px;padding:5px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;outline:none;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:11px/16px var(--dsw-font-family,system-ui)}
.dsh-mcs-search:focus{border-color:var(--dsw-alias-state-business-primary)}
.dsh-mcs-toollist{display:flex;flex-direction:column;max-height:220px;overflow:auto;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-base)}
.dsh-mcs-tool{display:flex;gap:12px;align-items:baseline;padding:7px 12px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2) 55%,transparent)}
.dsh-mcs-tool:last-child{border-bottom:0}
.dsh-mcs-tool code{flex:none;max-width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-state-business-primary);font:650 11px/16px ui-monospace,SFMono-Regular,Menlo,monospace}
.dsh-mcs-tool span{flex:1;min-width:0;color:var(--dsw-alias-label-tertiary);font-size:10.5px;line-height:15px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.dsh-mcs-tools-empty{padding:14px;color:var(--dsw-alias-label-tertiary);font-size:11px;text-align:center}
.dsh-mcs-filterbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

/* ---- json drawer, errors, empty ---- */
.dsh-mcs-drawer{overflow:hidden;border:1px solid color-mix(in srgb,var(--dsw-alias-state-business-primary) 28%,var(--dsw-alias-border-l2));border-radius:13px;background:var(--dsw-alias-bg-layer-1);box-shadow:var(--dsw-shadow-lv2)}
.dsh-mcs-drawer-inner{display:flex;flex-direction:column;gap:8px;padding:14px}
.dsh-mcs-json{width:100%;padding:9px 11px;border:1px solid var(--dsw-alias-border-l2);border-radius:9px;outline:none;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}
.dsh-mcs-json:focus{border-color:var(--dsw-alias-state-business-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--dsw-alias-state-business-primary) 12%,transparent)}
.dsh-mcs-errors{border:1px solid color-mix(in srgb,var(--dsw-alias-state-error-primary) 55%,transparent);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 7%,transparent);border-radius:10px;padding:9px 12px;font-size:11.5px;line-height:17px;color:var(--dsw-alias-state-error-primary)}
.dsh-mcs-errors strong{display:block;margin-bottom:3px}
.dsh-mcs-errors ul{margin:0;padding-left:16px}
.dsh-mcs-empty{padding:44px 24px;border:1px dashed var(--dsw-alias-border-l2);border-radius:13px;text-align:center}
.dsh-mcs-empty p{margin:0 0 14px;color:var(--dsw-alias-label-tertiary);font-size:11.5px;line-height:18px}
.dsh-mcs-spin{display:inline-block;width:12px;height:12px;border:2px solid var(--dsw-alias-border-l2);border-top-color:var(--dsw-alias-state-business-primary);border-radius:50%;animation:dsh-mcs-spin .7s linear infinite}
@keyframes dsh-mcs-spin{to{transform:rotate(360deg)}}
/* ---- compact density ---- */
.dsh-mcs--compact{gap:10px;padding:14px clamp(12px,2vw,28px) 32px;font-size:11.5px}
.dsh-mcs--compact .dsh-mcs-stats{gap:8px}
.dsh-mcs--compact .dsh-mcs-stat{padding:8px 12px;border-radius:10px}
.dsh-mcs--compact .dsh-mcs-stat>strong{font-size:17px;line-height:23px}
.dsh-mcs--compact .dsh-mcs-card-head{padding:8px 12px;gap:9px}
.dsh-mcs--compact .dsh-mcs-card{border-radius:11px}
.dsh-mcs--compact .dsh-mcs-body{padding:10px 12px 12px;gap:10px}
.dsh-mcs--compact .dsh-mcs-cmd{font-size:11px}
.dsh-mcs--compact .dsh-mcs-toollist{max-height:150px}

/* ---- drag & drop ---- */
.dsh-mcs-drag{opacity:.45;border-style:dashed}
.dsh-mcs-card[data-droptarget="1"]{border-color:var(--dsw-alias-state-business-primary);box-shadow:0 -2px 0 0 var(--dsw-alias-state-business-primary) inset}

/* ---- preset chips ---- */
.dsh-mcs-presets{display:flex;flex-wrap:wrap;gap:6px}
.dsh-mcs-preset{display:inline-flex;min-height:26px;align-items:center;padding:2px 11px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-secondary);font:650 10.5px/16px var(--dsw-font-family,system-ui);cursor:pointer;transition:color .15s,border-color .15s}
.dsh-mcs-preset:hover{border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 45%,var(--dsw-alias-border-l2));color:var(--dsw-alias-state-business-primary)}

/* ---- executions table ---- */
.dsh-mcs-exec{display:flex;flex-direction:column;gap:8px}
.dsh-mcs-exec-title{margin:0;font-size:11px;font-weight:700;line-height:17px;color:var(--dsw-alias-label-secondary);text-transform:uppercase;letter-spacing:.06em}
.dsh-mcs-exectable{width:100%;border-collapse:collapse;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);font-variant-numeric:tabular-nums}
.dsh-mcs-exectable th{padding:7px 12px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-tertiary);font-size:10px;font-weight:700;text-align:left;text-transform:uppercase;letter-spacing:.05em}
.dsh-mcs-exectable td{padding:6px 12px;border-top:1px solid color-mix(in srgb,var(--dsw-alias-border-l2) 55%,transparent);font-size:11px;line-height:16px;vertical-align:middle}
.dsh-mcs-exectable code{color:var(--dsw-alias-state-business-primary);font:650 10.5px/15px ui-monospace,SFMono-Regular,Menlo,monospace}
.dsh-mcs-exec-ok{color:var(--dsw-alias-state-success-primary);font-weight:650}
.dsh-mcs-exec-err{color:var(--dsw-alias-state-error-primary);font-weight:650}

/* ---- diagnose panel ---- */
.dsh-mcs-diag{display:flex;flex-direction:column;gap:6px;border-top:1px dashed var(--dsw-alias-border-l2);padding-top:10px}
.dsh-mcs-diag-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}
.dsh-mcs-diag-cell{padding:7px 11px;border:1px solid var(--dsw-alias-border-l2);border-radius:9px;background:var(--dsw-alias-bg-base)}
.dsh-mcs-diag-cell>span{display:block;color:var(--dsw-alias-label-tertiary);font-size:9.5px;font-weight:650;text-transform:uppercase;letter-spacing:.06em}
.dsh-mcs-diag-cell>strong{display:block;margin-top:1px;font-size:12px;line-height:17px}
.dsh-mcs-diag-error{color:var(--dsw-alias-state-error-primary);font:11px/16px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}

/* ---- executions footer / pager / clear ---- */
.dsh-mcs-exec-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.dsh-mcs-pager{display:flex;align-items:center;gap:6px;color:var(--dsw-alias-label-secondary);font-size:11px;font-variant-numeric:tabular-nums}
.dsh-mcs-pager .dsh-mcs-btn{min-height:24px;min-width:26px;padding:1px 8px;font-size:12px}
.dsh-mcs-btn--danger2{border-color:var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 12%,transparent);color:var(--dsw-alias-state-error-primary)}
.dsh-mcs-exec-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

/* ---- tools preview popover ---- */
.dsh-mcs-card{position:relative}
.dsh-mcs-toolscount--btn{cursor:pointer;border:1px solid transparent;transition:filter .15s,border-color .15s}
.dsh-mcs-toolscount--btn:hover{filter:brightness(1.12);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 40%,transparent)}
.dsh-mcs-popbackdrop{position:fixed;inset:0;z-index:40}
.dsh-mcs-pop{z-index:41;display:flex;flex-direction:column;gap:8px;padding:12px;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1);box-shadow:var(--dsw-shadow-lv3);animation:dsh-mcs-pop-in .14s ease-out;overflow:hidden}
@keyframes dsh-mcs-pop-in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.dsh-mcs-pop .dsh-mcs-toollist{flex:1;min-height:0}
.dsh-mcs-pop .dsh-mcs-tools-head{flex:none}

/* ---- polish ---- */
.dsh-mcs-body{animation:dsh-mcs-body-in .16s ease-out}
@keyframes dsh-mcs-body-in{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
.dsh-mcs-stat{transition:transform .15s,border-color .15s}
.dsh-mcs-stat:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 30%,var(--dsh-alias-border-l2,var(--dsw-alias-border-l2)))}
.dsh-mcs-btn:focus-visible,.dsh-mcs-preset:focus-visible,.dsh-mcs-toolscount--btn:focus-visible{outline:2px solid color-mix(in srgb,var(--dsw-alias-state-business-primary) 55%,transparent);outline-offset:1px}
.dsh-mcs-exectable tbody tr{transition:background .12s}
.dsh-mcs-exectable tbody tr:hover{background:var(--dsw-alias-interactive-bg-hover)}
.dsh-mcs-tool{transition:background .12s}
.dsh-mcs-tool:hover{background:var(--dsh-alias-interactive-bg-hover)}
.dsh-mcs-name,.dsh-mcs-cmd code{cursor:default}

`;
function installStyles() {
  const existing = document.getElementById(STYLE_ID);
  if (existing !== null) return () => void 0;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = CSS_TEXT;
  document.head.append(style);
  return () => {
    style.remove();
  };
}

// src/client/index.ts
var name = "dsh-mcp-studio-client";
var inject = ["slots", "locale", "connection"];
function apply(ctx) {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), "dsh-mcp-studio: locale");
  ctx.effect(() => installStyles(), "dsh-mcp-studio: styles");
  const scope = createStudioScope(ctx.connection);
  const controller = new StudioController(scope);
  const face = controller.inject();
  const t = ctx.locale.bind(NS);
  ctx.slots.inject("settings.section", () => ctx.slots.register({
    name: "settings.section",
    id: "mcp-studio",
    order: 110,
    label: () => t("nav")
  }, createStudioPage(face, t, () => scope.status(), (id) => scope.diagnose(id), () => scope.clearExecutions())));
}
return module.exports; } });
//# sourceMappingURL=client.js.map
