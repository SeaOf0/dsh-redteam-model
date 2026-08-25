/**
 * Design tokens for the Redteam Manager settings section.
 *
 * The page is intentionally compact: 12px body text, 10-12px card radii,
 * and only the 2px top strip / numeric value of a stat card carries
 * semantic color. Every color rides --dsw-alias-* theme tokens so the light
 * and dark skins both work; the values after the comma are light-mode
 * fallbacks for hosts that do not define a token.
 */

const STYLE_ID = 'dsh-redteam-model-styles'

const CSS_TEXT = String.raw`
.dsh-rtm,.dsh-rtm *{box-sizing:border-box}
.dsh-rtm{display:flex;min-height:100%;flex-direction:column;gap:16px;padding:20px clamp(16px,3vw,40px) 44px;color:var(--dsw-alias-label-primary,#1f2329);font-family:var(--dsw-font-family,system-ui);font-size:12px;line-height:18px}

/* ---- header ---- */
.dsh-rtm-head{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;flex-wrap:wrap}
.dsh-rtm-title{margin:0;font-size:17px;line-height:26px;font-weight:700;letter-spacing:-.01em}
.dsh-rtm-sub{margin:3px 0 0;color:var(--dsw-alias-label-secondary,#57606a);font-size:11.5px;line-height:18px;max-width:680px}
.dsh-rtm-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}

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

/* ---- cards / sections ---- */
.dsh-rtm-card{border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:12px;background:var(--dsw-alias-bg-layer-1,#fff);overflow:hidden}
.dsh-rtm-section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 14px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l2,#e5e6eb) 55%,transparent)}
.dsh-rtm-section-title{margin:0;font-size:11px;font-weight:700;line-height:17px;color:var(--dsw-alias-label-secondary,#57606a);text-transform:uppercase;letter-spacing:.06em}

.dsh-rtm-batchbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 14px;border:1px solid var(--dsw-alias-border-l2,#e5e6eb);border-radius:12px;background:var(--dsw-alias-bg-layer-1,#fff)}
.dsh-rtm-batchbar-hint{margin-left:auto;color:var(--dsw-alias-label-tertiary,#8a919f);font-size:10.5px;line-height:16px}

/* ---- modes ---- */
.dsh-rtm-modes{display:flex;flex-direction:column}
.dsh-rtm-mode-state{display:inline-flex;align-items:center;gap:6px;margin-left:auto;color:var(--dsw-alias-label-secondary,#57606a);font-size:10.5px;font-weight:650;line-height:16px;white-space:nowrap}
.dsh-rtm-mode-body{display:flex;flex-direction:column;gap:10px;padding:4px 16px 14px}
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
  .dsh-rtm-stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .dsh-rtm-stat{padding:9px 12px;border-radius:10px}
  .dsh-rtm-stat>strong{font-size:18px;line-height:24px}
  .dsh-rtm-plugin-row{align-items:flex-start;flex-wrap:wrap;gap:8px 12px}
  .dsh-rtm-plugin-actions{flex:1 1 100%;justify-content:flex-end;padding-top:2px}
  .dsh-rtm-batchbar-hint{margin-left:0;flex-basis:100%}
}

/* ---- reduced motion ---- */
@media (prefers-reduced-motion: reduce){
  .dsh-rtm-spin,.dsh-rtm-progress--indeterminate .dsh-rtm-progress-fill{animation:none}
  .dsh-rtm-progress-fill{transition:none}
}
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
