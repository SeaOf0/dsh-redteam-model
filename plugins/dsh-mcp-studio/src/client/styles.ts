/**
 * Design system for the MCP Studio page, installed once per client boot.
 * Every color rides the harness `--dsw-alias-*` theme tokens so both the
 * light and dark skins render correctly. No icon or emoji glyphs anywhere:
 * hierarchy comes from type scale, spacing, and status color alone.
 */

const STYLE_ID = 'dsh-mcp-studio-styles'

const CSS_TEXT = String.raw`
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

`

export function installStyles(): () => void {
  const existing = document.getElementById(STYLE_ID)
  if (existing !== null) return () => undefined
  const style = document.createElement('style')
  style.id = STYLE_ID
  style.textContent = CSS_TEXT
  document.head.append(style)
  return () => {
    style.remove()
  }
}
