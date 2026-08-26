window.__ModuleLoader__.load({ id: "@dsh-external/dsh-redteam-model", factory: (require) => {
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

// src/client/AdminPage.tsx
var import_react2 = require("react");
var import_dsh_client_ui_primitives6 = require("@deepseek-ai/dsh-client-ui-primitives");

// src/client/contracts.ts
var CHANNEL = "/dsh-redteam-model";

// src/conversationViewState.ts
var DEFAULT_CONVERSATION_VIEW_SETTINGS = Object.freeze({
  showCampaignMemory: true,
  showAttackAtlas: true,
  showRedteamResults: true,
  showHunter: true,
  showWebshellManager: true
});
function effectiveConversationViewSettings(snapshot) {
  return snapshot.status === "ready" && snapshot.value !== void 0 ? snapshot.value : DEFAULT_CONVERSATION_VIEW_SETTINGS;
}
function conversationViewWriteApplied(snapshot, field, expected) {
  return snapshot.status === "ready" && snapshot.value?.[field] === expected;
}

// src/client/conversationViewSettings.ts
var CONVERSATION_VIEW_SETTINGS_NAMESPACE = "redteam-manager-ui";
var VIEW_FIELD_BY_PLUGIN = {
  "dsh-campaign-memory": "showCampaignMemory",
  "dsh-attack-atlas": "showAttackAtlas",
  "dsh-redteam-results": "showRedteamResults",
  "dsh-hunter": "showHunter",
  "dsh-webshell-mgr": "showWebshellManager"
};
var VIEW_FIELDS = [
  "showCampaignMemory",
  "showAttackAtlas",
  "showRedteamResults",
  "showHunter",
  "showWebshellManager"
];
function decodeConversationViewSettings(section) {
  if (typeof section !== "object" || section === null || Array.isArray(section)) return void 0;
  const candidate = section;
  if (VIEW_FIELDS.some((field) => typeof candidate[field] !== "boolean")) return void 0;
  return {
    showCampaignMemory: candidate.showCampaignMemory,
    showAttackAtlas: candidate.showAttackAtlas,
    showRedteamResults: candidate.showRedteamResults,
    showHunter: candidate.showHunter,
    showWebshellManager: candidate.showWebshellManager
  };
}

// src/client/controller.ts
function messageOf(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}
var AdminController = class {
  constructor(connection) {
    this.connection = connection;
  }
  async status() {
    return this.call("status", {});
  }
  async start(request) {
    return this.call("operation/start", request);
  }
  async cancel(id) {
    return this.call("operation/cancel", { id });
  }
  async clear() {
    return this.call("operations/clear", {});
  }
  inject() {
    return {
      status: () => this.status(),
      start: (request) => this.start(request),
      cancel: (id) => this.cancel(id),
      clear: () => this.clear()
    };
  }
  async call(endpoint, payload) {
    const result = await this.connection.rpc.call(CHANNEL, endpoint, payload);
    if (result.ok !== true) {
      const detail = result.error?.message ?? "unknown error";
      throw new Error(`[dsh-redteam-model] ${endpoint} failed: ${detail}`);
    }
    return result.value;
  }
};
function errorMessage(error) {
  return messageOf(error);
}

// src/client/ConfirmDialog.tsx
var import_dsh_client_ui_primitives = require("@deepseek-ai/dsh-client-ui-primitives");
var import_jsx_runtime = require("react/jsx-runtime");
function ConfirmDialog({
  open,
  targets,
  title,
  description,
  confirmLabel,
  cancelLabel,
  busy,
  t,
  onClose,
  onConfirm
}) {
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(
    import_dsh_client_ui_primitives.Modal,
    {
      open,
      onClose,
      title,
      description,
      closeLabel: cancelLabel,
      footer: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_dsh_client_ui_primitives.Button, { variant: "ghost", onClick: onClose, children: cancelLabel }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_dsh_client_ui_primitives.Button, { variant: "primary", className: "dsh-rtm-btn--danger", disabled: busy, onClick: onConfirm, children: confirmLabel })
      ] }),
      children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "dsh-rtm-muted", children: t("confirmTargets") }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", { className: "dsh-rtm-confirm-list", children: targets.map((target) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: target }, target)) }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { className: "dsh-rtm-confirm-note", children: t("confirmUninstallDesc") })
      ]
    }
  );
}

// src/client/ModeSection.tsx
var import_react = require("react");
var import_dsh_client_ui_primitives2 = require("@deepseek-ai/dsh-client-ui-primitives");
var import_jsx_runtime2 = require("react/jsx-runtime");
function modeDot(state) {
  if (state === "ok") return "done";
  if (state === "error") return "error";
  return "warning";
}
function modeLabelKey(state) {
  if (state === "ok") return "modeStateOk";
  if (state === "missing") return "modeStateMissing";
  if (state === "stale") return "modeStateStale";
  return "modeStateError";
}
function ModeSection({
  modes,
  t,
  busy,
  pending,
  onDeploy,
  onRepair
}) {
  const [openIds, setOpenIds] = (0, import_react.useState)(() => /* @__PURE__ */ new Set());
  const toggle = (0, import_react.useCallback)((id) => {
    setOpenIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  return /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("section", { className: "dsh-rtm-card", children: [
    /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-rtm-section-head", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("h3", { className: "dsh-rtm-section-title", children: t("modesTitle") }) }),
    modes.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("p", { className: "dsh-rtm-empty", children: t("modesEmpty") }) : /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-rtm-modes", children: modes.map((mode) => {
      const labelKey = modeLabelKey(mode.linkState);
      const disabled = busy || pending || mode.linkState === "ok";
      const state = /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("span", { className: "dsh-rtm-mode-state", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(import_dsh_client_ui_primitives2.StateDot, { state: modeDot(mode.linkState), size: 7 }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t(labelKey) })
      ] });
      const rowActions = /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("span", { className: "dsh-rtm-mode-actions", children: [
        state,
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          import_dsh_client_ui_primitives2.Button,
          {
            size: "sm",
            variant: "outline",
            disabled,
            onClick: (event) => {
              event.stopPropagation();
              onDeploy(mode);
            },
            children: t("modeDeploy")
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
          import_dsh_client_ui_primitives2.Button,
          {
            size: "sm",
            variant: "outline",
            disabled,
            onClick: (event) => {
              event.stopPropagation();
              onRepair(mode);
            },
            children: t("modeRepair")
          }
        )
      ] });
      return /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
        import_dsh_client_ui_primitives2.DisclosureRow,
        {
          icon: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(import_dsh_client_ui_primitives2.IconAgentPresetOutline16, { size: 14 }),
          title: mode.name,
          open: openIds.has(mode.id),
          expandable: true,
          expandOnRowClick: true,
          onToggle: () => toggle(mode.id),
          collapsedContent: rowActions,
          keepContentWhenOpen: true,
          className: "dsh-rtm-disclosure",
          children: /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-rtm-mode-body", children: [
            /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-rtm-mode-summary", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: "dsh-rtm-muted", children: mode.summary }) }),
            mode.linkPath !== void 0 && mode.linkPath !== "" ? /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "dsh-rtm-path", children: [
              /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("modeLinkPath") }),
              /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("code", { title: mode.linkPath, children: mode.linkPath })
            ] }) : /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "dsh-rtm-path", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { children: t("modeNoPath") }) })
          ] })
        },
        mode.id
      );
    }) })
  ] });
}

// src/client/OperationsPanel.tsx
var import_dsh_client_ui_primitives3 = require("@deepseek-ai/dsh-client-ui-primitives");
var import_jsx_runtime3 = require("react/jsx-runtime");
function opDot(state) {
  if (state === "running") return "ongoing";
  if (state === "queued") return "warning";
  if (state === "done") return "done";
  if (state === "warned") return "warning";
  if (state === "cancelled") return "warning";
  return "error";
}
function opLabelKey(state) {
  if (state === "queued") return "opQueued";
  if (state === "running") return "opRunning";
  if (state === "done") return "opDone";
  if (state === "warned") return "opWarned";
  if (state === "cancelled") return "opCancelled";
  return "opFailed";
}
function kindLabelKey(kind) {
  if (kind === "deploy-modes") return "opKindDeployModes";
  if (kind === "install") return "opKindInstall";
  if (kind === "update") return "opKindUpdate";
  if (kind === "uninstall") return "opKindUninstall";
  return "opKindRepair";
}
function OperationsPanel({
  operations,
  t,
  busy,
  pending,
  onCancel,
  onClear
}) {
  const settled = operations.filter((op) => op.state === "done" || op.state === "warned" || op.state === "failed" || op.state === "cancelled").length;
  return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("section", { className: "dsh-rtm-card", children: [
    /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-rtm-section-head", children: [
      /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("h3", { className: "dsh-rtm-section-title", children: t("operationsTitle") }),
      /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
        import_dsh_client_ui_primitives3.Button,
        {
          size: "sm",
          variant: "ghost",
          disabled: busy || pending || settled === 0,
          onClick: onClear,
          children: t("opClear")
        }
      )
    ] }),
    operations.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("p", { className: "dsh-rtm-empty", children: t("opEmpty") }) : /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-rtm-ops", children: operations.map((op) => {
      const cancellable = op.state === "queued";
      return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-rtm-op", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-rtm-op-head", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("span", { className: "dsh-rtm-op-state", children: [
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(import_dsh_client_ui_primitives3.StateDot, { state: opDot(op.state), size: 7 }),
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { children: t(opLabelKey(op.state)) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-rtm-op-kind", children: t(kindLabelKey(op.kind)) }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("span", { className: "dsh-rtm-op-target", title: op.target, children: op.target }),
          cancellable && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
            import_dsh_client_ui_primitives3.Button,
            {
              size: "sm",
              variant: "ghost",
              disabled: pending,
              onClick: () => onCancel(op.id),
              children: t("opCancel")
            }
          )
        ] }),
        op.state === "running" && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-rtm-op-foot", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
            "div",
            {
              className: op.percent === null || op.percent === void 0 ? "dsh-rtm-progress-track dsh-rtm-progress--indeterminate" : "dsh-rtm-progress-track",
              role: "progressbar",
              "aria-label": t("opProgress"),
              "aria-valuemin": 0,
              "aria-valuemax": 100,
              "aria-valuenow": op.percent ?? void 0,
              children: /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
                "div",
                {
                  className: "dsh-rtm-progress-fill",
                  style: op.percent === null || op.percent === void 0 ? void 0 : { width: `${op.percent}%` }
                }
              )
            }
          ),
          op.percent !== null && op.percent !== void 0 && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("span", { className: "dsh-rtm-progress-value", children: [
            Math.round(op.percent),
            "%"
          ] })
        ] }),
        op.detail !== void 0 && op.detail !== "" && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "dsh-rtm-op-detail", children: op.detail }),
        op.error !== void 0 && op.error !== "" && /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "dsh-rtm-op-error", children: [
          t("opError"),
          ": ",
          op.error
        ] })
      ] }, op.id);
    }) })
  ] });
}

// src/client/OverviewPanel.tsx
var import_dsh_client_ui_primitives4 = require("@deepseek-ai/dsh-client-ui-primitives");

// src/client/StatusSummary.tsx
var import_jsx_runtime4 = require("react/jsx-runtime");
function StatusSummary({
  summary,
  runningCount,
  t
}) {
  const modesReady = summary.modesReady === summary.modesTotal;
  const pluginsInstalled = summary.pluginsInstalled === summary.pluginsTotal;
  const updates = summary.updatesAvailable > 0;
  const running = runningCount > 0;
  return /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "dsh-rtm-stats", children: [
    /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: modesReady ? "dsh-rtm-stat dsh-rtm-stat--ok" : "dsh-rtm-stat dsh-rtm-stat--warn", children: [
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { children: t("statModesReady") }),
      /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("strong", { children: [
        summary.modesReady,
        "/",
        summary.modesTotal
      ] })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: pluginsInstalled ? "dsh-rtm-stat dsh-rtm-stat--ok" : "dsh-rtm-stat dsh-rtm-stat--warn", children: [
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { children: t("statPluginsInstalled") }),
      /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("strong", { children: [
        summary.pluginsInstalled,
        "/",
        summary.pluginsTotal
      ] })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: updates ? "dsh-rtm-stat dsh-rtm-stat--warn" : "dsh-rtm-stat", children: [
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { children: t("statUpdates") }),
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("strong", { children: summary.updatesAvailable })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: running ? "dsh-rtm-stat dsh-rtm-stat--business" : "dsh-rtm-stat", children: [
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { children: t("statRunning") }),
      /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("strong", { children: runningCount })
    ] })
  ] });
}

// src/client/OverviewPanel.tsx
var import_jsx_runtime5 = require("react/jsx-runtime");
function OverviewPanel({
  status,
  runningCount,
  t,
  onNavigate
}) {
  const modeAttention = status.modes.filter((mode) => !mode.ready).length;
  const pluginAttention = status.plugins.filter((plugin) => plugin.installState !== "installed").length;
  const operationWarnings = status.operations.filter((operation) => operation.state === "failed" || operation.state === "warned").length;
  const profileError = status.summary.profileError !== void 0 && status.summary.profileError !== "";
  const overall = profileError ? "error" : runningCount > 0 ? "busy" : modeAttention > 0 || pluginAttention > 0 ? "attention" : "healthy";
  const overallLabel = overall === "error" ? t("overallError") : overall === "busy" ? t("overallBusy") : overall === "attention" ? t("overallAttention") : t("overallHealthy");
  return /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("div", { className: "dsh-rtm-overview", children: [
    /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(StatusSummary, { summary: status.summary, runningCount, t }),
    /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("section", { className: `dsh-rtm-overall dsh-rtm-overall--${overall}`, "aria-live": "polite", children: [
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
        import_dsh_client_ui_primitives4.StateDot,
        {
          state: overall === "healthy" ? "done" : overall === "busy" ? "ongoing" : overall === "error" ? "error" : "warning",
          size: 8
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("span", { children: t("overallLabel") }),
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("strong", { children: overallLabel })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("section", { className: "dsh-rtm-card", children: [
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("div", { className: "dsh-rtm-section-head", children: /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("h3", { className: "dsh-rtm-section-title", children: t("attentionTitle") }) }),
      /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("div", { className: "dsh-rtm-attention-list", children: [
        /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
          AttentionRow,
          {
            label: t("overviewModesLabel"),
            value: modeAttention,
            detail: modeAttention === 0 ? t("overviewModesHealthy") : t("overviewModesAttention"),
            attention: modeAttention > 0,
            actionLabel: t("viewDetails"),
            onClick: () => onNavigate("modes")
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
          AttentionRow,
          {
            label: t("overviewPluginsLabel"),
            value: pluginAttention,
            detail: pluginAttention === 0 ? t("overviewPluginsHealthy") : t("overviewPluginsAttention"),
            attention: pluginAttention > 0,
            actionLabel: t("viewDetails"),
            onClick: () => onNavigate("plugins")
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
          AttentionRow,
          {
            label: t("overviewOperationsLabel"),
            value: operationWarnings,
            detail: `${t("overviewRunning")}: ${runningCount} \xB7 ${t("overviewWarnings")}: ${operationWarnings}`,
            attention: runningCount > 0 || operationWarnings > 0,
            actionLabel: t("viewDetails"),
            onClick: () => onNavigate("logs")
          }
        )
      ] })
    ] })
  ] });
}
function AttentionRow({
  label,
  value,
  detail,
  attention,
  actionLabel,
  onClick
}) {
  return /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("div", { className: "dsh-rtm-attention-row", children: [
    /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(import_dsh_client_ui_primitives4.StateDot, { state: attention ? "warning" : "done", size: 7 }),
    /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("div", { className: "dsh-rtm-attention-main", children: [
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("strong", { children: label }),
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("span", { children: detail })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("span", { className: attention ? "dsh-rtm-attention-count is-attention" : "dsh-rtm-attention-count", children: value }),
    /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(import_dsh_client_ui_primitives4.Button, { size: "sm", variant: "ghost", onClick, children: actionLabel })
  ] });
}

// src/client/PluginSection.tsx
var import_dsh_client_ui_primitives5 = require("@deepseek-ai/dsh-client-ui-primitives");
var import_jsx_runtime6 = require("react/jsx-runtime");
function pluginDot(state) {
  if (state === "installed") return "done";
  if (state === "broken") return "error";
  return "warning";
}
function pluginLabelKey(state) {
  if (state === "installed") return "pluginStateInstalled";
  if (state === "update-available") return "pluginStateUpdateAvailable";
  if (state === "broken") return "pluginStateBroken";
  return "pluginStateNotInstalled";
}
function versionLabel(plugin, t) {
  const installed = plugin.installedVersion ?? t("versionUnknown");
  const latest = plugin.latestVersion;
  if (latest !== void 0 && plugin.installState === "update-available") {
    return `${installed} ${t("versionSeparator")} ${latest}`;
  }
  return installed;
}
function isEnabledInProfile(plugin) {
  return plugin.installState !== "not-installed";
}
function conversationViewField(plugin) {
  return VIEW_FIELD_BY_PLUGIN[plugin.name];
}
function PluginSection({
  plugins,
  t,
  busy,
  pending,
  visibility,
  visibilityWritable,
  visibilityPending,
  onSetEnabled,
  onSetViewVisible,
  onUpdate,
  onRepair
}) {
  const conversationViewPlugins = plugins.filter((plugin) => conversationViewField(plugin) !== void 0);
  return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(import_jsx_runtime6.Fragment, { children: [
    /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("section", { className: "dsh-rtm-card", children: [
      /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "dsh-rtm-section-head", children: /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("h3", { className: "dsh-rtm-section-title", children: t("pluginViewSettingsTitle") }) }),
      /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-view-settings-summary", children: [
        /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("p", { className: "dsh-rtm-view-settings-note", children: t("pluginViewSettingsScope") }),
        !visibilityWritable && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("p", { className: "dsh-rtm-view-settings-unavailable", role: "status", children: t("pluginViewSettingsUnavailable") })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "dsh-rtm-view-settings-grid", children: conversationViewPlugins.map((plugin) => {
        const viewField = conversationViewField(plugin);
        if (viewField === void 0) return null;
        return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("label", { className: "dsh-rtm-switch-row dsh-rtm-view-setting", title: t("pluginViewScopeHint"), children: [
          /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("span", { className: "dsh-rtm-switch-copy", children: [
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { children: plugin.title }),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("small", { children: t("pluginViewLiveHint") })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("span", { className: "dsh-rtm-switch", children: [
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(
              "input",
              {
                type: "checkbox",
                role: "switch",
                checked: visibility[viewField],
                disabled: !visibilityWritable || visibilityPending !== null,
                "aria-label": `${plugin.title}: ${t("pluginShowConversationView")}`,
                onChange: (event) => onSetViewVisible(viewField, event.target.checked)
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("i", { "aria-hidden": "true" })
          ] })
        ] }, plugin.name);
      }) })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("section", { className: "dsh-rtm-card", children: [
      /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "dsh-rtm-section-head", children: /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("h3", { className: "dsh-rtm-section-title", children: t("pluginsTitle") }) }),
      plugins.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("p", { className: "dsh-rtm-empty", children: t("pluginsEmpty") }) : /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "dsh-rtm-plugins", children: plugins.map((plugin) => {
        const labelKey = pluginLabelKey(plugin.installState);
        const state = plugin.installState;
        return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-plugin-row", children: [
          /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(import_dsh_client_ui_primitives5.IconCordisPluginOutline14, { size: 14 }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-plugin-main", children: [
            /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-plugin-title-row", children: [
              /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { className: "dsh-rtm-plugin-name", title: plugin.name, children: plugin.title }),
              /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { className: "dsh-rtm-plugin-plane", children: plugin.mountPlane === "preset" ? t("pluginPresetPlane") : t("pluginHostPlane") })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("p", { className: "dsh-rtm-plugin-desc", children: plugin.description }),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-plugin-meta", children: [
              /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("span", { className: "dsh-rtm-plugin-state", children: [
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(import_dsh_client_ui_primitives5.StateDot, { state: pluginDot(state), size: 7 }),
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { children: t(labelKey) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { className: "dsh-rtm-version", children: versionLabel(plugin, t) })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "dsh-rtm-plugin-actions", children: [
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "dsh-rtm-plugin-switches", children: /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("label", { className: "dsh-rtm-switch-row", title: t("pluginEnabledRestartHint"), children: [
              /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("span", { className: "dsh-rtm-switch-copy", children: [
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { children: t("pluginEnabledInProfile") }),
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("small", { children: t("pluginEnabledRestartHint") })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("span", { className: "dsh-rtm-switch", children: [
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(
                  "input",
                  {
                    type: "checkbox",
                    role: "switch",
                    checked: isEnabledInProfile(plugin),
                    disabled: busy || pending,
                    "aria-label": `${plugin.title}: ${t("pluginEnabledInProfile")}`,
                    onChange: (event) => onSetEnabled(plugin, event.target.checked)
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("i", { "aria-hidden": "true" })
              ] })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(
              import_dsh_client_ui_primitives5.Button,
              {
                size: "sm",
                variant: "outline",
                disabled: busy || pending || state !== "update-available",
                onClick: () => onUpdate(plugin),
                children: t("pluginUpdate")
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(
              import_dsh_client_ui_primitives5.Button,
              {
                size: "sm",
                variant: "outline",
                disabled: busy || pending || state !== "broken",
                onClick: () => onRepair(plugin),
                children: t("pluginRepair")
              }
            )
          ] })
        ] }, plugin.name);
      }) })
    ] })
  ] });
}

// src/client/AdminPage.tsx
var import_jsx_runtime7 = require("react/jsx-runtime");
var ACTIVE_POLL_MS = 2e3;
var IDLE_POLL_MS = 1e4;
var MANAGER_PAGES = [
  { id: "overview", label: "pageOverview" },
  { id: "modes", label: "pageModes" },
  { id: "plugins", label: "pagePlugins" },
  { id: "logs", label: "pageLogs" }
];
function hasActiveOperations(status) {
  return status !== null && (status.summary.busy || status.operations.some((op) => op.state === "queued" || op.state === "running"));
}
function createAdminPage(face, t, visibilityScope) {
  return function AdminPage() {
    const [activePage, setActivePage] = (0, import_react2.useState)("overview");
    const [status, setStatus] = (0, import_react2.useState)(null);
    const [error, setError] = (0, import_react2.useState)(null);
    const [pending, setPending] = (0, import_react2.useState)(false);
    const [uninstallTargets, setUninstallTargets] = (0, import_react2.useState)(null);
    const [visibilitySnapshot, setVisibilitySnapshot] = (0, import_react2.useState)(() => visibilityScope.getSnapshot());
    const [visibilityPending, setVisibilityPending] = (0, import_react2.useState)(null);
    const refresh = (0, import_react2.useCallback)(async () => {
      try {
        const next = await face.status();
        setStatus(next);
        setError(null);
      } catch (cause) {
        setError(errorMessage(cause));
      }
    }, [face]);
    (0, import_react2.useEffect)(() => {
      let alive = true;
      let timer;
      const tick = async () => {
        try {
          const next = await face.status();
          if (!alive) return;
          setStatus(next);
          setError(null);
          timer = window.setTimeout(() => void tick(), hasActiveOperations(next) ? ACTIVE_POLL_MS : IDLE_POLL_MS);
        } catch (cause) {
          if (!alive) return;
          setError(errorMessage(cause));
          timer = window.setTimeout(() => void tick(), IDLE_POLL_MS);
        }
      };
      void tick();
      return () => {
        alive = false;
        if (timer !== void 0) window.clearTimeout(timer);
      };
    }, [face]);
    (0, import_react2.useEffect)(() => {
      const publish = () => setVisibilitySnapshot(visibilityScope.getSnapshot());
      const unsubscribe = visibilityScope.subscribe(publish);
      publish();
      return unsubscribe;
    }, [visibilityScope]);
    const visibility = effectiveConversationViewSettings(visibilitySnapshot);
    const visibilityWritable = visibilitySnapshot.status === "ready" && visibilitySnapshot.mode === "host" && visibilitySnapshot.writable;
    const setViewVisible = (0, import_react2.useCallback)(async (field, visible) => {
      if (!visibilityWritable) return;
      setVisibilityPending(field);
      setError(null);
      try {
        await visibilityScope.set(field, visible);
        const settled = visibilityScope.getSnapshot();
        setVisibilitySnapshot(settled);
        if (!conversationViewWriteApplied(settled, field, visible)) {
          throw new Error(t("pluginViewSettingsSaveFailed"));
        }
      } catch (cause) {
        setError(errorMessage(cause));
      } finally {
        setVisibilityPending(null);
      }
    }, [t, visibilityScope, visibilityWritable]);
    const runStart = (0, import_react2.useCallback)(async (request) => {
      setPending(true);
      setError(null);
      try {
        await face.start(request);
        await refresh();
      } catch (cause) {
        setError(errorMessage(cause));
      } finally {
        setPending(false);
      }
    }, [face, refresh]);
    const runCancel = (0, import_react2.useCallback)(async (id) => {
      setPending(true);
      setError(null);
      try {
        await face.cancel(id);
        await refresh();
      } catch (cause) {
        setError(errorMessage(cause));
      } finally {
        setPending(false);
      }
    }, [face, refresh]);
    const runClear = (0, import_react2.useCallback)(async () => {
      setPending(true);
      setError(null);
      try {
        await face.clear();
        await refresh();
      } catch (cause) {
        setError(errorMessage(cause));
      } finally {
        setPending(false);
      }
    }, [face, refresh]);
    const confirmUninstall = (0, import_react2.useCallback)(async () => {
      if (uninstallTargets === null) return;
      const names = uninstallTargets.map((plugin) => plugin.name);
      setPending(true);
      setError(null);
      try {
        await face.start({
          kind: "uninstall",
          target: names.length === 1 ? names[0] ?? "" : "installed",
          targets: names.length === 1 ? void 0 : names
        });
        setUninstallTargets(null);
        await refresh();
      } catch (cause) {
        setError(errorMessage(cause));
      } finally {
        setPending(false);
      }
    }, [face, refresh, uninstallTargets]);
    const busy = hasActiveOperations(status);
    const runningCount = status?.operations.filter((op) => op.state === "queued" || op.state === "running").length ?? 0;
    const missingPlugins = status?.plugins.filter((plugin) => plugin.installState === "not-installed") ?? [];
    const updatablePlugins = status?.plugins.filter((plugin) => plugin.installState === "update-available") ?? [];
    const installedPlugins = status?.plugins.filter((plugin) => plugin.installState !== "not-installed") ?? [];
    if (status === null) {
      return /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm", children: [
        error !== null && /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-error", role: "alert", children: [
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-title", children: t("errorBannerTitle") }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-message", children: error })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-loading", children: [
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-spin", "aria-label": t("loading") }),
          t("loading")
        ] })
      ] });
    }
    const batchDisabled = busy || pending;
    const confirmOpen = uninstallTargets !== null;
    const confirmTargets = uninstallTargets?.map((plugin) => plugin.name) ?? [];
    const activePageButtonId = `dsh-rtm-page-${activePage}`;
    return /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm", children: [
      /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-head", children: [
        /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("h2", { className: "dsh-rtm-title", children: t("title") }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("p", { className: "dsh-rtm-sub", children: t("subtitle") })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-toolbar", children: [
          busy && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-muted", children: t("busyHint") }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
            import_dsh_client_ui_primitives6.Button,
            {
              size: "sm",
              variant: "outline",
              icon: /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(import_dsh_client_ui_primitives6.IconRefreshOutline16, { size: 14 }),
              disabled: pending,
              onClick: () => void refresh(),
              children: t("refresh")
            }
          )
        ] })
      ] }),
      error !== null && /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-error", role: "alert", children: [
        /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-title", children: t("requestFailed") }),
        /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-message", children: error })
      ] }),
      status.summary.profileError !== void 0 && status.summary.profileError !== "" && /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-error", role: "alert", children: [
        /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-title", children: t("profileError") }),
        /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-error-message", children: status.summary.profileError })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("p", { className: "dsh-rtm-restart-hint", children: t("restartHint") }),
      /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("nav", { className: "dsh-rtm-page-nav", "aria-label": t("managerPages"), children: MANAGER_PAGES.map((page) => /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
        "button",
        {
          id: `dsh-rtm-page-${page.id}`,
          type: "button",
          className: activePage === page.id ? "dsh-rtm-page-button is-active" : "dsh-rtm-page-button",
          "aria-current": activePage === page.id ? "page" : void 0,
          "aria-controls": "dsh-rtm-page-content",
          onClick: () => setActivePage(page.id),
          children: t(page.label)
        },
        page.id
      )) }),
      /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { id: "dsh-rtm-page-content", className: "dsh-rtm-page-content", role: "region", "aria-labelledby": activePageButtonId, children: [
        activePage === "overview" && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(OverviewPanel, { status, runningCount, t, onNavigate: setActivePage }),
        activePage === "modes" && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
          ModeSection,
          {
            modes: status.modes,
            t,
            busy,
            pending,
            onDeploy: (mode) => void runStart({ kind: "deploy-modes", target: mode.id }),
            onRepair: (mode) => void runStart({ kind: "repair", target: mode.id })
          }
        ),
        activePage === "plugins" && /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)(import_jsx_runtime7.Fragment, { children: [
          /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "dsh-rtm-batchbar", children: [
            /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)(
              import_dsh_client_ui_primitives6.Button,
              {
                size: "sm",
                variant: "outline",
                disabled: batchDisabled || missingPlugins.length === 0,
                onClick: () => void runStart({
                  kind: "install",
                  target: "missing",
                  targets: missingPlugins.map((plugin) => plugin.name)
                }),
                children: [
                  t("batchInstallMissing"),
                  " (",
                  missingPlugins.length,
                  ")"
                ]
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)(
              import_dsh_client_ui_primitives6.Button,
              {
                size: "sm",
                variant: "outline",
                disabled: batchDisabled || updatablePlugins.length === 0,
                onClick: () => void runStart({
                  kind: "update",
                  target: "updates",
                  targets: updatablePlugins.map((plugin) => plugin.name)
                }),
                children: [
                  t("batchUpdateAll"),
                  " (",
                  updatablePlugins.length,
                  ")"
                ]
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)(
              import_dsh_client_ui_primitives6.Button,
              {
                size: "sm",
                variant: "ghost",
                className: "dsh-rtm-btn--danger",
                disabled: batchDisabled || installedPlugins.length === 0,
                onClick: () => setUninstallTargets(installedPlugins),
                children: [
                  t("batchUninstallAll"),
                  " (",
                  installedPlugins.length,
                  ")"
                ]
              }
            ),
            busy && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("span", { className: "dsh-rtm-batchbar-hint", children: t("busyHint") })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
            PluginSection,
            {
              plugins: status.plugins,
              t,
              busy,
              pending,
              visibility,
              visibilityWritable,
              visibilityPending,
              onSetEnabled: (plugin, enabled) => {
                if (enabled) {
                  void runStart({ kind: "install", target: plugin.name });
                  return;
                }
                setUninstallTargets([plugin]);
              },
              onSetViewVisible: (field, visible) => void setViewVisible(field, visible),
              onUpdate: (plugin) => void runStart({ kind: "update", target: plugin.name }),
              onRepair: (plugin) => void runStart({ kind: "repair", target: plugin.name })
            }
          )
        ] }),
        activePage === "logs" && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
          OperationsPanel,
          {
            operations: status.operations,
            t,
            busy,
            pending,
            onCancel: (id) => void runCancel(id),
            onClear: () => void runClear()
          }
        )
      ] }),
      confirmOpen && uninstallTargets !== null && /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
        ConfirmDialog,
        {
          open: true,
          targets: confirmTargets,
          title: uninstallTargets.length > 1 ? t("confirmUninstallAllTitle") : t("confirmUninstallTitle"),
          description: t("confirmUninstallDesc"),
          confirmLabel: t("confirmConfirm"),
          cancelLabel: t("confirmCancel"),
          busy: pending,
          t,
          onClose: () => setUninstallTargets(null),
          onConfirm: () => void confirmUninstall()
        }
      )
    ] });
  };
}

// src/client/locales.ts
var NS = "redteam-manager";
var en = {
  nav: "Redteam Manager",
  title: "Redteam Manager",
  subtitle: "Install, update and remove the security research modes and their runtime plugins for the current profile.",
  refresh: "Refresh",
  loading: "Loading\u2026",
  errorBannerTitle: "Unable to load manager status",
  profileError: "The DSH profile manifest cannot be read. Fix it manually before installing or uninstalling plugins.",
  requestFailed: "Request failed",
  retry: "Retry",
  managerPages: "Manager pages",
  pageOverview: "Overview",
  pageModes: "Modes",
  pagePlugins: "Plugins",
  pageLogs: "Logs",
  overallLabel: "Overall status",
  overallHealthy: "Healthy",
  overallAttention: "Attention required",
  overallBusy: "Operation running",
  overallError: "Profile error",
  attentionTitle: "Attention",
  overviewModesLabel: "Security modes",
  overviewModesHealthy: "All modes are ready",
  overviewModesAttention: "Modes need deployment or repair",
  overviewPluginsLabel: "Runtime plugins",
  overviewPluginsHealthy: "All plugins are installed and current",
  overviewPluginsAttention: "Plugins are missing, outdated, or broken",
  overviewOperationsLabel: "Operation history",
  overviewRunning: "Running",
  overviewWarnings: "Warnings or failures",
  viewDetails: "View details",
  statModesReady: "Modes ready",
  statPluginsInstalled: "Plugins installed",
  statUpdates: "Updates",
  statRunning: "Running",
  batchInstallMissing: "Install missing",
  batchUpdateAll: "Update all",
  batchUninstallAll: "Uninstall all",
  busyHint: "An operation is running. Other actions are disabled.",
  restartHint: "Host-plane plugins and manager updates take effect after restarting dsh web; refresh the page to update copied-mode status.",
  modesTitle: "Security modes",
  modesEmpty: "No modes reported by the host.",
  modeStateOk: "ok",
  modeStateMissing: "missing",
  modeStateStale: "stale",
  modeStateError: "error",
  modeLinkPath: "Link path",
  modeDeploy: "Deploy",
  modeRepair: "Repair",
  modeNoPath: "No link path reported",
  pluginsTitle: "Runtime plugins",
  pluginsEmpty: "No plugins reported by the host.",
  pluginStateNotInstalled: "not installed",
  pluginStateInstalled: "installed",
  pluginStateUpdateAvailable: "update available",
  pluginStateBroken: "broken",
  pluginInstall: "Install",
  pluginUpdate: "Update",
  pluginRepair: "Repair",
  pluginUninstall: "Uninstall",
  pluginEnabledInProfile: "Enabled in current profile",
  pluginEnabledRestartHint: "Restart dsh web to apply",
  pluginShowConversationView: "Show conversation tab",
  pluginViewSettingsTitle: "Conversation tabs",
  pluginViewLiveHint: "Applies immediately",
  pluginViewScopeHint: "Saved for this DSH_HOME; tools and data remain active",
  pluginViewSettingsScope: "Conversation tab visibility is saved DSH_HOME-wide and applies live. Hiding a tab does not disable its tools or data.",
  pluginViewSettingsUnavailable: "Conversation tab preferences are unavailable or read-only in this browser.",
  pluginViewSettingsSaveFailed: "The conversation tab preference was not saved. The previous value has been restored.",
  pluginVersion: "Version",
  pluginLatest: "latest",
  pluginNotInstalled: "not installed",
  pluginHostPlane: "host",
  pluginPresetPlane: "preset",
  versionUnknown: "\u2014",
  versionSeparator: "\u2192",
  operationsTitle: "Operations",
  opQueued: "Queued",
  opRunning: "Running",
  opDone: "Done",
  opWarned: "Finished with warnings",
  opFailed: "Failed",
  opEmpty: "No operations yet.",
  opProgress: "Progress",
  opClear: "Clear finished",
  opCancel: "Cancel",
  opDetail: "Detail",
  opError: "Error",
  opCancelled: "Cancelled",
  opKindDeployModes: "Deploy modes",
  opKindInstall: "Install",
  opKindUpdate: "Update",
  opKindUninstall: "Uninstall",
  opKindRepair: "Repair",
  confirmUninstallTitle: "Uninstall plugin",
  confirmUninstallAllTitle: "Uninstall plugins",
  confirmUninstallDesc: "This removes the plugin from the current profile after confirmation. Its tools and UI will be unavailable after restart; plugin data is kept.",
  confirmTargets: "Targets",
  confirmCancel: "Cancel",
  confirmConfirm: "Confirm"
};
var zh = {
  nav: "\u7EA2\u961F\u6A21\u578B\u7BA1\u7406",
  title: "\u7EA2\u961F\u6A21\u578B\u7BA1\u7406\u53F0",
  subtitle: "\u4E3A\u5F53\u524D profile \u5B89\u88C5\u3001\u66F4\u65B0\u4E0E\u5378\u8F7D\u5B89\u5168\u7814\u7A76\u6A21\u5F0F\u53CA\u5176\u8FD0\u884C\u65F6\u63D2\u4EF6\u3002",
  refresh: "\u5237\u65B0",
  loading: "\u52A0\u8F7D\u4E2D\u2026",
  errorBannerTitle: "\u65E0\u6CD5\u52A0\u8F7D\u7BA1\u7406\u53F0\u72B6\u6001",
  profileError: "DSH profile \u6E05\u5355\u65E0\u6CD5\u8BFB\u53D6\uFF0C\u8BF7\u5148\u624B\u52A8\u4FEE\u590D\u540E\u518D\u5B89\u88C5\u6216\u5378\u8F7D\u63D2\u4EF6\u3002",
  requestFailed: "\u8BF7\u6C42\u5931\u8D25",
  retry: "\u91CD\u8BD5",
  managerPages: "\u7BA1\u7406\u9875\u9762",
  pageOverview: "\u6982\u89C8",
  pageModes: "\u6A21\u5F0F",
  pagePlugins: "\u63D2\u4EF6",
  pageLogs: "\u65E5\u5FD7",
  overallLabel: "\u603B\u4F53\u72B6\u6001",
  overallHealthy: "\u8FD0\u884C\u6B63\u5E38",
  overallAttention: "\u9700\u8981\u5173\u6CE8",
  overallBusy: "\u64CD\u4F5C\u8FDB\u884C\u4E2D",
  overallError: "Profile \u5F02\u5E38",
  attentionTitle: "\u6CE8\u610F\u9879",
  overviewModesLabel: "\u5B89\u5168\u6A21\u5F0F",
  overviewModesHealthy: "\u6240\u6709\u6A21\u5F0F\u5747\u5DF2\u5C31\u7EEA",
  overviewModesAttention: "\u6709\u6A21\u5F0F\u9700\u8981\u90E8\u7F72\u6216\u4FEE\u590D",
  overviewPluginsLabel: "\u8FD0\u884C\u65F6\u63D2\u4EF6",
  overviewPluginsHealthy: "\u6240\u6709\u63D2\u4EF6\u5747\u5DF2\u5B89\u88C5\u4E14\u4E3A\u6700\u65B0\u72B6\u6001",
  overviewPluginsAttention: "\u6709\u63D2\u4EF6\u7F3A\u5931\u3001\u53EF\u66F4\u65B0\u6216\u5F02\u5E38",
  overviewOperationsLabel: "\u64CD\u4F5C\u5386\u53F2",
  overviewRunning: "\u8FD0\u884C\u4E2D",
  overviewWarnings: "\u8B66\u544A\u6216\u5931\u8D25",
  viewDetails: "\u67E5\u770B\u8BE6\u60C5",
  statModesReady: "\u6A21\u5F0F\u5C31\u7EEA",
  statPluginsInstalled: "\u63D2\u4EF6\u5DF2\u88C5",
  statUpdates: "\u53EF\u66F4\u65B0",
  statRunning: "\u8FD0\u884C\u4E2D",
  batchInstallMissing: "\u5B89\u88C5\u7F3A\u5931",
  batchUpdateAll: "\u5168\u90E8\u66F4\u65B0",
  batchUninstallAll: "\u5168\u90E8\u5378\u8F7D",
  busyHint: "\u6709\u64CD\u4F5C\u6B63\u5728\u8FD0\u884C\uFF0C\u5176\u4ED6\u64CD\u4F5C\u5DF2\u7981\u7528\u3002",
  restartHint: "\u5BBF\u4E3B\u5E73\u9762\u63D2\u4EF6\u53CA\u7BA1\u7406\u5668\u81EA\u8EAB\u66F4\u65B0\u9700\u8981\u91CD\u542F dsh web \u540E\u751F\u6548\uFF1B\u6A21\u5F0F\u590D\u5236\u72B6\u6001\u5237\u65B0\u9875\u9762\u5373\u53EF\u66F4\u65B0\u3002",
  modesTitle: "\u5B89\u5168\u6A21\u5F0F",
  modesEmpty: "\u5BBF\u4E3B\u672A\u4E0A\u62A5\u4EFB\u4F55\u6A21\u5F0F\u3002",
  modeStateOk: "\u6B63\u5E38",
  modeStateMissing: "\u7F3A\u5931",
  modeStateStale: "\u8FC7\u671F",
  modeStateError: "\u5F02\u5E38",
  modeLinkPath: "\u94FE\u63A5\u8DEF\u5F84",
  modeDeploy: "\u90E8\u7F72",
  modeRepair: "\u4FEE\u590D",
  modeNoPath: "\u672A\u4E0A\u62A5\u94FE\u63A5\u8DEF\u5F84",
  pluginsTitle: "\u8FD0\u884C\u65F6\u63D2\u4EF6",
  pluginsEmpty: "\u5BBF\u4E3B\u672A\u4E0A\u62A5\u4EFB\u4F55\u63D2\u4EF6\u3002",
  pluginStateNotInstalled: "\u672A\u5B89\u88C5",
  pluginStateInstalled: "\u5DF2\u5B89\u88C5",
  pluginStateUpdateAvailable: "\u53EF\u66F4\u65B0",
  pluginStateBroken: "\u5F02\u5E38",
  pluginInstall: "\u5B89\u88C5",
  pluginUpdate: "\u66F4\u65B0",
  pluginRepair: "\u4FEE\u590D",
  pluginUninstall: "\u5378\u8F7D",
  pluginEnabledInProfile: "\u5728\u5F53\u524D profile \u542F\u7528",
  pluginEnabledRestartHint: "\u91CD\u542F dsh web \u540E\u751F\u6548",
  pluginShowConversationView: "\u663E\u793A\u5BF9\u8BDD\u6807\u7B7E",
  pluginViewSettingsTitle: "\u5BF9\u8BDD\u6807\u7B7E",
  pluginViewLiveHint: "\u7ACB\u5373\u751F\u6548",
  pluginViewScopeHint: "\u4FDD\u5B58\u5230\u5F53\u524D DSH_HOME\uFF1B\u5DE5\u5177\u548C\u6570\u636E\u4ECD\u4FDD\u6301\u8FD0\u884C",
  pluginViewSettingsScope: "\u5BF9\u8BDD\u6807\u7B7E\u53EF\u89C1\u6027\u6309 DSH_HOME \u6301\u4E45\u5316\u5E76\u5B9E\u65F6\u751F\u6548\uFF1B\u9690\u85CF\u6807\u7B7E\u4E0D\u4F1A\u505C\u7528\u5176\u5DE5\u5177\u6216\u6570\u636E\u3002",
  pluginViewSettingsUnavailable: "\u5F53\u524D\u6D4F\u89C8\u5668\u65E0\u6CD5\u4FEE\u6539\u5BF9\u8BDD\u6807\u7B7E\u504F\u597D\uFF0C\u6216\u8BE5\u8BBE\u7F6E\u4E3A\u53EA\u8BFB\u72B6\u6001\u3002",
  pluginViewSettingsSaveFailed: "\u5BF9\u8BDD\u6807\u7B7E\u504F\u597D\u672A\u80FD\u4FDD\u5B58\uFF0C\u5DF2\u6062\u590D\u4E3A\u539F\u503C\u3002",
  pluginVersion: "\u7248\u672C",
  pluginLatest: "\u6700\u65B0",
  pluginNotInstalled: "\u672A\u5B89\u88C5",
  pluginHostPlane: "\u5BBF\u4E3B",
  pluginPresetPlane: "\u9884\u8BBE",
  versionUnknown: "\u2014",
  versionSeparator: "\u2192",
  operationsTitle: "\u64CD\u4F5C\u65E5\u5FD7",
  opQueued: "\u6392\u961F\u4E2D",
  opRunning: "\u8FD0\u884C\u4E2D",
  opDone: "\u5DF2\u5B8C\u6210",
  opWarned: "\u5DF2\u5B8C\u6210\uFF08\u6709\u8B66\u544A\uFF09",
  opFailed: "\u5931\u8D25",
  opEmpty: "\u6682\u65E0\u64CD\u4F5C\u3002",
  opProgress: "\u8FDB\u5EA6",
  opClear: "\u6E05\u9664\u5DF2\u5B8C\u6210",
  opCancel: "\u53D6\u6D88",
  opDetail: "\u8BE6\u60C5",
  opError: "\u9519\u8BEF",
  opCancelled: "\u5DF2\u53D6\u6D88",
  opKindDeployModes: "\u90E8\u7F72\u6A21\u5F0F",
  opKindInstall: "\u5B89\u88C5",
  opKindUpdate: "\u66F4\u65B0",
  opKindUninstall: "\u5378\u8F7D",
  opKindRepair: "\u4FEE\u590D",
  confirmUninstallTitle: "\u5378\u8F7D\u63D2\u4EF6",
  confirmUninstallAllTitle: "\u5378\u8F7D\u63D2\u4EF6",
  confirmUninstallDesc: "\u786E\u8BA4\u540E\u4F1A\u4ECE\u5F53\u524D profile \u79FB\u9664\u8BE5\u63D2\u4EF6\uFF1B\u91CD\u542F\u540E\u5176\u5DE5\u5177\u548C\u754C\u9762\u5C06\u4E0D\u53EF\u7528\uFF0C\u63D2\u4EF6\u6570\u636E\u4F1A\u4FDD\u7559\u3002",
  confirmTargets: "\u76EE\u6807",
  confirmCancel: "\u53D6\u6D88",
  confirmConfirm: "\u786E\u8BA4"
};

// src/client/styles.ts
var STYLE_ID = "dsh-redteam-model-styles";
var CSS_TEXT = String.raw`
.dsh-rtm,.dsh-rtm *{box-sizing:border-box}
.dsh-rtm{display:flex;min-height:100%;flex-direction:column;gap:16px;padding:20px clamp(16px,3vw,40px) 44px;color:var(--dsw-alias-label-primary,#1f2329);font-family:var(--dsw-font-family,system-ui);font-size:12px;line-height:18px}

/* ---- header ---- */
.dsh-rtm-head{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;flex-wrap:wrap}
.dsh-rtm-title{margin:0;font-size:17px;line-height:26px;font-weight:700;letter-spacing:-.01em}
.dsh-rtm-sub{margin:3px 0 0;color:var(--dsw-alias-label-secondary,#57606a);font-size:11.5px;line-height:18px;max-width:680px}
.dsh-rtm-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}

.dsh-rtm-page-nav{display:flex;min-width:0;overflow-x:auto;border-bottom:1px solid var(--dsw-alias-border-l2,#e5e6eb);scrollbar-width:thin}
.dsh-rtm-page-button{position:relative;flex:none;min-width:84px;padding:8px 14px;border:0;border-radius:8px 8px 0 0;background:transparent;color:var(--dsw-alias-label-secondary,#57606a);font:650 11.5px/18px var(--dsw-font-family,system-ui);cursor:pointer}
.dsh-rtm-page-button::after{content:"";position:absolute;right:10px;bottom:-1px;left:10px;height:2px;border-radius:2px 2px 0 0;background:transparent}
.dsh-rtm-page-button:hover{background:var(--dsw-alias-interactive-bg-hover,color-mix(in srgb,var(--dsw-alias-label-primary,#1f2329) 6%,transparent));color:var(--dsw-alias-label-primary,#1f2329)}
.dsh-rtm-page-button.is-active{background:var(--dsw-alias-bg-layer-1,#fff);color:var(--dsw-alias-state-business-primary,#2563eb);font-weight:750}
.dsh-rtm-page-button.is-active::after{background:var(--dsw-alias-state-business-primary,#2563eb)}
.dsh-rtm-page-content,.dsh-rtm-overview{display:flex;min-width:0;flex-direction:column;gap:16px}

.dsh-rtm-error{border:1px solid color-mix(in srgb,var(--dsw-alias-state-error-primary,#d92d20) 55%,var(--dsw-alias-border-l2,#e5e6eb));background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#d92d20) 7%,transparent);border-radius:10px;padding:9px 12px;color:var(--dsw-alias-state-error-primary,#d92d20);font-size:11.5px;line-height:17px}
.dsh-rtm-error-title{display:block;font-weight:700}
.dsh-rtm-error-message{margin-top:2px;color:var(--dsw-alias-label-secondary,#57606a)}

.dsh-rtm-loading{display:flex;align-items:center;gap:8px;padding:32px 4px;color:var(--dsw-alias-label-secondary,#57606a)}
.dsh-rtm-spin{display:inline-block;width:12px;height:12px;border:2px solid var(--dsw-alias-border-l2,#e5e6eb);border-top-color:var(--dsw-alias-state-business-primary,#2563eb);border-radius:50%;animation:dsh-rtm-spin .7s linear infinite;flex:none}
@keyframes dsh-rtm-spin{to{transform:rotate(360deg)}}

/* ---- stats strip ---- */
.dsh-rtm-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.dsh-rtm-stat{position:relative;overflow:hidden;padding:11px 14px;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:12px;background:var(--dsw-alias-bg-layer-1,#fff)}
.dsh-rtm-stat>span{display:block;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10px;font-weight:650;line-height:15px;text-transform:uppercase;letter-spacing:.07em}
.dsh-rtm-stat>strong{display:block;margin-top:3px;font-size:22px;line-height:30px;font-weight:700;letter-spacing:-.02em;color:var(--dsw-alias-label-primary,#1f2329);font-variant-numeric:tabular-nums}
.dsh-rtm-stat::after{content:"";position:absolute;top:0;left:0;width:100%;height:2px;background:transparent}
.dsh-rtm-stat--ok>strong{color:var(--dsw-alias-state-success-primary,#16a34a)}
.dsh-rtm-stat--ok::after{background:color-mix(in srgb,var(--dsw-alias-state-success-primary,#16a34a) 55%,transparent)}
.dsh-rtm-stat--warn>strong{color:var(--dsw-alias-state-warn-primary,#d97706)}
.dsh-rtm-stat--warn::after{background:color-mix(in srgb,var(--dsw-alias-state-warn-primary,#d97706) 55%,transparent)}
.dsh-rtm-stat--business>strong{color:var(--dsw-alias-state-business-primary,#2563eb)}
.dsh-rtm-stat--business::after{background:color-mix(in srgb,var(--dsw-alias-state-business-primary,#2563eb) 55%,transparent)}
.dsh-rtm-stat--error>strong{color:var(--dsw-alias-state-error-primary,#d92d20)}
.dsh-rtm-stat--error::after{background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#d92d20) 55%,transparent)}

/* ---- overview ---- */
.dsh-rtm-overall{display:flex;align-items:center;gap:8px;padding:10px 14px;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:10px;background:var(--dsw-alias-bg-layer-1,#fff);color:var(--dsw-alias-label-secondary,#57606a)}
.dsh-rtm-overall>strong{color:var(--dsw-alias-label-primary,#1f2329)}
.dsh-rtm-overall--healthy>strong{color:var(--dsw-alias-state-success-primary,#16a34a)}
.dsh-rtm-overall--attention>strong,.dsh-rtm-overall--busy>strong{color:var(--dsw-alias-state-warn-primary,#d97706)}
.dsh-rtm-overall--error>strong{color:var(--dsw-alias-state-error-primary,#d92d20)}
.dsh-rtm-attention-list{display:flex;flex-direction:column}
.dsh-rtm-attention-row{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent)}
.dsh-rtm-attention-row:last-child{border-bottom:0}
.dsh-rtm-attention-main{display:flex;min-width:0;flex:1;flex-direction:column}
.dsh-rtm-attention-main>strong{font-size:12px;line-height:18px}
.dsh-rtm-attention-main>span{color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}
.dsh-rtm-attention-count{min-width:28px;padding:1px 8px;border-radius:999px;background:var(--dsw-alias-bg-layer-2,#e9eaee);color:var(--dsw-alias-label-secondary,#57606a);font-weight:700;text-align:center;font-variant-numeric:tabular-nums}
.dsh-rtm-attention-count.is-attention{background:color-mix(in srgb,var(--dsw-alias-state-warn-primary,#d97706) 12%,transparent);color:var(--dsw-alias-state-warn-primary,#d97706)}

/* ---- cards / sections ---- */
.dsh-rtm-card{border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:12px;background:var(--dsw-alias-bg-layer-1,#fff);overflow:hidden}
.dsh-rtm-section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent)}
.dsh-rtm-section-title{margin:0;font-size:11px;font-weight:700;line-height:17px;color:var(--dsw-alias-label-secondary,#57606a);text-transform:uppercase;letter-spacing:.06em}

.dsh-rtm-batchbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 14px;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:12px;background:var(--dsw-alias-bg-layer-1,#fff)}
.dsh-rtm-restart-hint{margin:0;padding:8px 12px;border:1px dashed color-mix(in srgb,var(--dsw-alias-state-warn-primary,#d97706) 45%,var(--dsw-alias-border-l2,#e5e6eb));border-radius:10px;background:color-mix(in srgb,var(--dsw-alias-state-warn-primary,#d97706) 6%,transparent);color:var(--dsw-alias-label-secondary,#57606a);font-size:11px;line-height:17px}
.dsh-rtm-batchbar-hint{margin-left:auto;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}

/* ---- modes ---- */
.dsh-rtm-modes{display:flex;flex-direction:column;gap:8px}
.dsh-rtm-disclosure{padding:6px 14px}
.dsh-rtm-mode-actions{display:inline-flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap;justify-content:flex-end}
.dsh-rtm-mode-actions .dsh-rtm-mode-state{margin-left:0}
.dsh-rtm-mode-state{display:inline-flex;align-items:center;gap:6px;margin-left:auto;color:var(--dsw-alias-label-secondary,#57606a);font-size:10.5px;font-weight:650;line-height:16px;white-space:nowrap}
.dsh-rtm-mode-body{display:flex;flex-direction:column;gap:10px;padding:4px 0 14px}
.dsh-rtm-mode-summary{display:flex;align-items:baseline;gap:8px;color:var(--dsw-alias-label-secondary,#57606a)}
.dsh-rtm-mode-summary .dsh-rtm-mode-state{margin-left:0}
.dsh-rtm-path{display:flex;align-items:baseline;gap:8px;min-width:0;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:11px}
.dsh-rtm-path code{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-state-business-primary,#2563eb);font:11px/17px ui-monospace,SFMono-Regular,Menlo,monospace;direction:ltr}
.dsh-rtm-actions{display:flex;gap:8px;flex-wrap:wrap}
.dsh-rtm-muted{color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}
.dsh-rtm-empty{padding:16px;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:11.5px;text-align:center}

/* ---- plugins ---- */
.dsh-rtm-plugins{display:flex;flex-direction:column}
.dsh-rtm-plugin-row{display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent)}
.dsh-rtm-plugin-row:last-child{border-bottom:0}
.dsh-rtm-plugin-main{display:flex;min-width:0;flex:1;flex-direction:column;gap:2px}
.dsh-rtm-plugin-title-row{display:flex;align-items:baseline;gap:8px;min-width:0}
.dsh-rtm-plugin-name{font-size:12.5px;font-weight:700;line-height:19px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dsh-rtm-plugin-plane{flex:none;padding:0 7px;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:999px;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:9px;font-weight:700;line-height:15px;text-transform:uppercase;letter-spacing:.06em}
.dsh-rtm-plugin-desc{margin:0;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:15px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dsh-rtm-plugin-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}
.dsh-rtm-plugin-state{display:inline-flex;align-items:center;gap:6px;color:var(--dsw-alias-label-secondary,#57606a);font-size:10.5px;font-weight:650;line-height:16px;white-space:nowrap}
.dsh-rtm-plugin-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;flex:none}
.dsh-rtm-version{font-variant-numeric:tabular-nums;white-space:nowrap}
.dsh-rtm-view-settings-summary{padding:9px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent);background:color-mix(in srgb,var(--dsw-alias-state-business-primary,#2563eb) 3%,transparent)}
.dsh-rtm-view-settings-note,.dsh-rtm-view-settings-unavailable{margin:0;color:var(--dsw-alias-label-secondary,#57606a);font-size:10.5px;line-height:16px}
.dsh-rtm-view-settings-unavailable{margin-top:3px;color:var(--dsw-alias-state-warn-primary,#d97706)}
.dsh-rtm-view-settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:12px 14px}
.dsh-rtm-view-setting{min-width:0;justify-content:space-between;padding:8px 10px;border:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 70%,transparent);border-radius:8px;background:var(--dsw-alias-bg-layer-2,#f7f8fa)}
.dsh-rtm-view-setting .dsh-rtm-switch-copy{align-items:flex-start}
.dsh-rtm-plugin-switches{display:flex;min-width:205px;flex-direction:column;align-items:stretch;gap:7px;margin-right:4px}
.dsh-rtm-switch-row{display:flex;align-items:center;justify-content:flex-end;gap:8px;min-width:176px;color:var(--dsw-alias-label-secondary,#57606a);font-size:11px;cursor:pointer}
.dsh-rtm-switch-copy{display:flex;min-width:0;flex:1;flex-direction:column;align-items:flex-end;line-height:1.25}
.dsh-rtm-switch-copy small{color:var(--dsw-alias-label-tertiary,#8a919f);font-size:9.5px}
.dsh-rtm-switch{position:relative;display:inline-block;flex:none;width:34px;height:19px}
.dsh-rtm-switch input{position:absolute;inset:0;z-index:1;margin:0;opacity:0;cursor:pointer}
.dsh-rtm-switch i{position:absolute;inset:0;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:999px;background:var(--dsw-alias-bg-layer-2,#e9eaee);transition:background .15s,border-color .15s}
.dsh-rtm-switch i::after{content:"";position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:left .15s}
.dsh-rtm-switch input:checked+i{border-color:transparent;background:var(--dsw-alias-state-business-primary,#2563eb)}
.dsh-rtm-switch input:checked+i::after{left:17px}
.dsh-rtm-switch input:focus-visible+i{outline:2px solid color-mix(in srgb,var(--dsw-alias-state-business-primary,#2563eb) 55%,transparent);outline-offset:2px}
.dsh-rtm-switch input:disabled{cursor:not-allowed}
.dsh-rtm-switch input:disabled+i{opacity:.5}
.dsh-rtm-switch-row:has(input:disabled){cursor:not-allowed}

/* ---- operations ---- */
.dsh-rtm-ops{display:flex;flex-direction:column}
.dsh-rtm-op{display:flex;flex-direction:column;gap:6px;padding:9px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent)}
.dsh-rtm-op:last-child{border-bottom:0}
.dsh-rtm-op-head{display:flex;align-items:center;gap:8px;min-width:0;flex-wrap:wrap}
.dsh-rtm-op-state{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-weight:650;line-height:16px;white-space:nowrap}
.dsh-rtm-op-target{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-label-primary,#1f2329);font-weight:650}
.dsh-rtm-op-kind{color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}
.dsh-rtm-op-detail{color:var(--dsw-alias-label-secondary,#57606a);font-size:10.5px;line-height:15px;word-break:break-word}
.dsh-rtm-op-error{color:var(--dsw-alias-state-error-primary,#d92d20);font-size:10.5px;line-height:15px;word-break:break-word}
.dsh-rtm-op-foot{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

.dsh-rtm-progress{display:flex;align-items:center;gap:8px;min-width:0}
.dsh-rtm-progress-track{position:relative;flex:1;min-width:120px;height:6px;overflow:hidden;border-radius:999px;background:var(--dsw-alias-bg-layer-2,#e9eaee)}
.dsh-rtm-progress-fill{height:100%;border-radius:inherit;background:var(--dsw-alias-state-business-primary,#2563eb);transition:width .2s ease}
.dsh-rtm-progress--indeterminate .dsh-rtm-progress-fill{width:35%;animation:dsh-rtm-indeterminate 1.1s ease-in-out infinite}
@keyframes dsh-rtm-indeterminate{0%{transform:translateX(-100%)}100%{transform:translateX(290%)}}
.dsh-rtm-progress-value{flex:none;min-width:34px;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10px;line-height:15px;font-variant-numeric:tabular-nums;text-align:right}

/* ---- confirm dialog ---- */
.dsh-rtm-confirm-list{margin:0;padding-left:18px;color:var(--dsw-alias-label-primary,#1f2329);font-size:12px;line-height:20px}
.dsh-rtm-confirm-note{margin:12px 0 0;color:var(--dsw-alias-label-secondary,#57606a);font-size:11.5px;line-height:17px}

/* ---- danger button (primitives have no danger variant) ---- */
.dsh-rtm-btn--danger{border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary,#d92d20) 45%,var(--dsw-alias-border-l2,#e5e6eb));color:var(--dsw-alias-state-error-primary,#d92d20)}
.dsh-rtm-btn--danger:hover:not(:disabled){border-color:var(--dsw-alias-state-error-primary,#d92d20);background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#d92d20) 10%,transparent)}

/* ---- focus / polish ---- */
.dsh-rtm .dsh-rtm-btn:focus-visible,
.dsh-rtm button:focus-visible{outline:2px solid color-mix(in srgb,var(--dsw-alias-state-business-primary,#2563eb) 55%,transparent);outline-offset:1px}

/* ---- responsive: two-column stats, wrapping plugin rows below 720px ---- */
@media (max-width:719px){
  .dsh-rtm{padding-inline:14px}
  .dsh-rtm-page-nav{margin-inline:-2px}
  .dsh-rtm-page-button{min-width:76px;padding-inline:12px}
  .dsh-rtm-stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .dsh-rtm-stat{padding:9px 12px;border-radius:10px}
  .dsh-rtm-stat>strong{font-size:18px;line-height:24px}
  .dsh-rtm-attention-row{align-items:flex-start;flex-wrap:wrap}
  .dsh-rtm-attention-main{flex-basis:calc(100% - 24px)}
  .dsh-rtm-plugin-row{align-items:flex-start;flex-wrap:wrap;gap:8px 12px}
  .dsh-rtm-plugin-actions{flex:1 1 100%;justify-content:flex-end;padding-top:2px}
  .dsh-rtm-view-settings-grid{grid-template-columns:1fr}
  .dsh-rtm-plugin-switches{flex:1 1 100%;width:100%;margin:0 0 2px}
  .dsh-rtm-switch-row{width:100%;justify-content:space-between}
  .dsh-rtm-switch-copy{align-items:flex-start}
  .dsh-rtm-batchbar-hint{margin-left:0;flex-basis:100%}
}

/* The Host settings shell is two-column by default; stack its navigation only
   while this page is selected on phone-sized viewports. */
@media (max-width:559px){
  [role="dialog"]:has(.dsh-rtm){flex-direction:column}
  [role="dialog"]:has(.dsh-rtm)>nav{width:100%;padding:10px 12px 0}
  [role="dialog"]:has(.dsh-rtm)>nav>:first-child{display:none}
  [role="dialog"]:has(.dsh-rtm)>nav>:last-child{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px;padding-bottom:8px}
  [role="dialog"]:has(.dsh-rtm)>nav>:last-child>button{width:100%!important;min-width:0;padding:7px 10px;white-space:normal}
  [role="dialog"]:has(.dsh-rtm)>:not(nav){width:100%;min-height:0}
  .dsh-rtm{padding-inline:10px}
  .dsh-rtm-stats{grid-template-columns:1fr}
}

/* ---- reduced motion ---- */
@media (prefers-reduced-motion: reduce){
  .dsh-rtm-spin,.dsh-rtm-progress--indeterminate .dsh-rtm-progress-fill{animation:none}
  .dsh-rtm-progress-fill,.dsh-rtm-switch i,.dsh-rtm-switch i::after{transition:none}
}
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
var name = "dsh-redteam-model-client";
var inject = ["slots", "locale", "connection", "settingsScope"];
function apply(ctx) {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), "dsh-redteam-model: locale");
  ctx.effect(() => installStyles(), "dsh-redteam-model: styles");
  const controller = new AdminController(ctx.connection);
  const face = controller.inject();
  const t = ctx.locale.bind(NS);
  const visibilityScope = ctx.settingsScope.bind({
    namespace: CONVERSATION_VIEW_SETTINGS_NAMESPACE,
    decode: decodeConversationViewSettings
  });
  ctx.slots.inject("settings.section", () => ctx.slots.register({
    name: "settings.section",
    id: "redteam-manager",
    order: 120,
    label: () => t("nav")
  }, createAdminPage(face, t, visibilityScope)));
}
return module.exports; } });
//# sourceMappingURL=client.js.map
