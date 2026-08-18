/** One server card: status dot, name, transport chip, summary, tool-count badge (opens a preview popover), switch, and delete. Config expands only on manual click. */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactElement } from 'react'
import type { DiagnoseReport, ServerDraft, ServerLive, Translate } from './contracts.js'
import { Field, PairEditor, ToggleSwitch } from './components.js'
import { serversToMcpJson } from './mcp-json.js'

/** Manual transport entry: typed text maps onto the two supported transports. */
function transportDisplay(value: 'stdio' | 'streamable-http'): string {
  return value === 'stdio' ? 'stdio' : 'http'
}

function parseTransportInput(text: string): 'stdio' | 'streamable-http' | undefined {
  const normalized = text.trim().toLowerCase().replace(/[\s_-]/g, '')
  if (normalized === '') return undefined
  if (normalized === 'stdio') return 'stdio'
  if (normalized === 'http' || normalized === 'sse' || normalized === 'streamablehttp') return 'streamable-http'
  return undefined
}

const stateLabel: Record<ServerLive['state'], 'stateConnected' | 'stateMounting' | 'stateUnreachable' | 'stateError' | 'stateDisabled'> = {
  connected: 'stateConnected',
  mounting: 'stateMounting',
  unreachable: 'stateUnreachable',
  error: 'stateError',
  disabled: 'stateDisabled',
}

const stateClass: Record<ServerLive['state'], string> = {
  connected: 'dsh-mcs-dot--ok',
  mounting: 'dsh-mcs-dot--busy',
  unreachable: '',
  error: 'dsh-mcs-dot--err',
  disabled: '',
}

const stateTextClass: Record<ServerLive['state'], string> = {
  connected: 'dsh-mcs-state--ok',
  mounting: 'dsh-mcs-state--busy',
  unreachable: 'dsh-mcs-state--off',
  error: 'dsh-mcs-state--err',
  disabled: 'dsh-mcs-state--off',
}

function ToolPopover(props: { live: ServerLive; t: Translate; pos: { top: number; left: number; width: number; maxHeight: number }; onClose(): void }): ReactElement {
  const { t } = props
  const [filter, setFilter] = useState('')
  const tools = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    if (needle === '') return props.live.tools
    return props.live.tools.filter(tool => tool.name.toLowerCase().includes(needle) || tool.description.toLowerCase().includes(needle))
  }, [filter, props.live.tools])
  return (
    <>
      <div className="dsh-mcs-popbackdrop" onClick={event => { event.stopPropagation(); props.onClose() }} />
      <div
        className="dsh-mcs-pop"
        role="dialog"
        aria-label={t('toolsTitle')}
        style={{ position: 'fixed', top: props.pos.top, left: props.pos.left, width: props.pos.width, maxHeight: props.pos.maxHeight }}
        onClick={event => event.stopPropagation()}
      >
      <div className="dsh-mcs-tools-head">
        <h4 className="dsh-mcs-tools-title">{props.live.name} · {props.live.toolCount} {t('toolsUnit')}</h4>
        <input
          className="dsh-mcs-search"
          autoFocus
          placeholder={t('toolsSearchPlaceholder')}
          value={filter}
          onChange={event => setFilter(event.target.value)}
          onClick={event => event.stopPropagation()}
        />
      </div>
      <div className="dsh-mcs-toollist">
        {tools.length === 0
          ? <div className="dsh-mcs-tools-empty">{filter.trim() === '' ? t('toolsWaiting') : t('toolsEmpty')}</div>
          : tools.map(tool => (
            <div key={tool.name} className="dsh-mcs-tool" title={tool.description}>
              <code>{tool.name}</code>
              <span>{tool.description}</span>
            </div>
          ))}
      </div>
      </div>
    </>
  )
}

export function ServerCard(props: {
  server: ServerDraft
  live: ServerLive | undefined
  open: boolean
  onToggle(): void
  t: Translate
  disabled: boolean
  onUpdate(next: ServerDraft): void
  onRemove(): void
  diagnose?(id: string): Promise<DiagnoseReport | { error: string }>
}): ReactElement {
  const { server, live, t } = props
  const set = (patch: Partial<ServerDraft>): void => props.onUpdate({ ...server, ...patch })
  const [transportText, setTransportText] = useState(() => transportDisplay(server.transport))
  const [copied, setCopied] = useState(false)
  const [diagBusy, setDiagBusy] = useState(false)
  const [toolsOpen, setToolsOpen] = useState(false)
  const badgeRef = useRef<HTMLButtonElement | null>(null)
  const [popPos, setPopPos] = useState<{ top: number; left: number; width: number; maxHeight: number } | undefined>(undefined)
  const [diag, setDiag] = useState<DiagnoseReport | { error: string } | undefined>(undefined)
  const runDiagnose = (): void => {
    if (props.diagnose === undefined || diagBusy) return
    setDiagBusy(true)
    setDiag(undefined)
    void props.diagnose(server.id).then(report => {
      setDiag(report)
      setDiagBusy(false)
    }, () => {
      setDiag({ error: 'request failed' })
      setDiagBusy(false)
    })
  }
  useEffect(() => {
    setTransportText(transportDisplay(server.transport))
  }, [server.transport])
  useEffect(() => {
    if (live?.state !== 'connected') setToolsOpen(false)
  }, [live?.state])

  /** Clamp the popover fully inside the viewport (flip/clamp/shrink), re-measured on scroll/resize while open. */
  const reposition = useCallback((initial: boolean) => {
    const badge = badgeRef.current
    const card = badge?.closest('.dsh-mcs-card') as HTMLElement | null
    if (badge === null || card === null) return
    const badgeRect = badge.getBoundingClientRect()
    if (!initial && (badgeRect.bottom < 0 || badgeRect.top > window.innerHeight)) {
      // Badge scrolled out of the viewport: close instead of hovering orphaned.
      setToolsOpen(false)
      return
    }
    const cardRect = card.getBoundingClientRect()
    const margin = 8
    const gap = 6
    const width = Math.min(520, window.innerWidth - margin * 2)
    const desired = Math.min(380, window.innerHeight - margin * 2)
    let top = badgeRect.bottom + gap
    if (top + desired > window.innerHeight - margin) top = badgeRect.top - gap - desired
    if (top < margin) top = margin
    const maxHeight = Math.max(160, Math.min(desired, window.innerHeight - margin - top))
    let left = cardRect.right - width
    if (left < margin) left = margin
    if (left + width > window.innerWidth - margin) left = window.innerWidth - margin - width
    setPopPos(previous => previous !== undefined
      && previous.top === top && previous.left === left && previous.width === width && previous.maxHeight === maxHeight
      ? previous
      : { top, left, width, maxHeight })
  }, [])

  useEffect(() => {
    if (!toolsOpen) {
      setPopPos(undefined)
      return
    }
    reposition(true)
    const re = (event?: Event) => {
      // Scrolling inside the popover's own list must not re-anchor it.
      const target = event !== undefined && event.type === 'scroll' ? event.target as Element | null : null
      if (target !== null && typeof target.closest === 'function' && target.closest('.dsh-mcs-pop') !== null) return
      reposition(false)
    }
    window.addEventListener('resize', re)
    window.addEventListener('scroll', re, true)
    return () => {
      window.removeEventListener('resize', re)
      window.removeEventListener('scroll', re, true)
    }
  }, [toolsOpen, reposition])
  const transportInvalid = parseTransportInput(transportText) === undefined && transportText.trim() !== ''
  const state = live === undefined ? (server.enabled ? 'mounting' : 'disabled') : live.state
  const summary = server.transport === 'stdio'
    ? `${server.command}${server.argsLine.trim() === '' ? '' : ` ${server.argsLine.trim()}`}`
    : server.url
  const toolCount = live?.toolCount ?? 0
  return (
    <div className={props.open ? 'dsh-mcs-card is-open' : server.enabled ? 'dsh-mcs-card' : 'dsh-mcs-card is-off'}>
      {toolsOpen && live !== undefined && live.state === 'connected' && popPos !== undefined && (
        <ToolPopover live={live} t={t} pos={popPos} onClose={() => setToolsOpen(false)} />
      )}
      <div
        className="dsh-mcs-card-head"
        role="button"
        tabIndex={0}
        aria-expanded={props.open}
        title={server.name === '' ? undefined : `${server.name} · ${summary}`}
        onClick={props.onToggle}
        onKeyDown={event => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            props.onToggle()
          }
        }}
      >
        <span className={`dsh-mcs-dot ${stateClass[state]}`} />
        <span className="dsh-mcs-name">{server.name === '' ? t('unnamedServer') : server.name}</span>
        <span className={server.transport === 'stdio' ? 'dsh-mcs-chip' : 'dsh-mcs-chip dsh-mcs-chip--http'}>
          {server.transport === 'stdio' ? 'stdio' : 'http'}
        </span>
        <span className="dsh-mcs-cmd"><code>{summary}</code></span>
        <span className={`dsh-mcs-state ${stateTextClass[state]}`}>{t(stateLabel[state])}</span>
        {state === 'connected' && (
          <button
            ref={node => {
              badgeRef.current = node
            }}
            type="button"
            className="dsh-mcs-toolscount dsh-mcs-toolscount--btn"
            title={t('toolsPreviewHint')}
            onClick={event => {
              event.stopPropagation()
              setToolsOpen(open => !open)
            }}
          >
            {toolCount} {t('toolsUnit')}
          </button>
        )}
        <ToggleSwitch checked={server.enabled} label={t('serverEnabled')} onChange={enabled => set({ enabled })} />
        <button type="button" className="dsh-mcs-iconbtn" title={t('removeServer')} aria-label={t('removeServer')}
          onClick={event => {
            event.stopPropagation()
            props.onRemove()
          }}
        >×</button>
        <button type="button" className="dsh-mcs-chevron" aria-hidden tabIndex={-1}>▶</button>
      </div>
      {state === 'error' && live?.error !== undefined && (
        <div className="dsh-mcs-carderr">{live.error}</div>
      )}
      {props.open && (
        <div className="dsh-mcs-body" onClick={event => event.stopPropagation()}>
          <div className="dsh-mcs-grid">
            <Field label={t('serverName')} hint={t('serverNameHint')}>
              <input value={server.name} onChange={event => set({ name: event.target.value })} />
            </Field>
            <Field label={t('transport')} hint={transportInvalid ? t('transportInvalid') : t('transportHint')}>
              <input
                value={transportText}
                spellCheck={false}
                placeholder="stdio | http"
                onChange={event => {
                  const text = event.target.value
                  setTransportText(text)
                  const parsed = parseTransportInput(text)
                  if (parsed !== undefined && parsed !== server.transport) set({ transport: parsed })
                }}
              />
            </Field>
            {server.transport === 'stdio' ? (
              <>
                <Field label={t('command')} hint={t('commandHint')}>
                  <input value={server.command} onChange={event => set({ command: event.target.value })} />
                </Field>
                <Field label={t('argsLine')} hint={t('argsLineHint')}>
                  <input value={server.argsLine} onChange={event => set({ argsLine: event.target.value })} />
                </Field>
                <Field label={t('cwd')} hint={t('cwdHint')}>
                  <input value={server.cwd} onChange={event => set({ cwd: event.target.value })} />
                </Field>
              </>
            ) : (
              <Field label={t('url')} hint={t('urlHint')}>
                <input value={server.url} onChange={event => set({ url: event.target.value })} />
              </Field>
            )}
            <Field label={t('toolCallTimeoutMs')}>
              <input
                type="number"
                min={1000}
                step={1000}
                value={server.toolCallTimeoutMs}
                onChange={event => {
                  const value = Number.parseInt(event.target.value, 10)
                  set({ toolCallTimeoutMs: Number.isFinite(value) ? Math.max(1000, value) : 60_000 })
                }}
              />
            </Field>
          </div>
          {server.transport === 'stdio' ? (
            <Field label={t('env')} hint={t('envHint')}>
              <PairEditor pairs={server.env} t={t} onChange={env => set({ env })} />
            </Field>
          ) : (
            <Field label={t('headers')} hint={t('headersHint')}>
              <PairEditor pairs={server.headers} t={t} onChange={headers => set({ headers })} />
            </Field>
          )}
          <div className="dsh-mcs-check">
            <input
              type="checkbox"
              id={`mcs-fail-${server.id}`}
              checked={server.failOnStartupError}
              onChange={event => set({ failOnStartupError: event.target.checked })}
            />
            <label htmlFor={`mcs-fail-${server.id}`}>{t('failOnStartupError')}</label>
            <small>{t('failOnStartupErrorHint')}</small>
          </div>
          <div className="dsh-mcs-toolbar">
            <button
              type="button"
              className="dsh-mcs-btn dsh-mcs-btn--ghost"
              onClick={() => {
                const json = serversToMcpJson([server])
                void navigator.clipboard?.writeText(json).then(
                  () => {
                    setCopied(true)
                    setTimeout(() => setCopied(false), 1600)
                  },
                  () => setCopied(false),
                )
              }}
            >
              {copied ? t('copied') : t('copyThisServer')}
            </button>
            {props.diagnose !== undefined && (
              <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" disabled={diagBusy} onClick={runDiagnose}>
                {diagBusy ? <span className="dsh-mcs-spin" /> : t('testConnection')}
              </button>
            )}
          </div>
          {diag !== undefined && (
            <div className="dsh-mcs-diag">
              {'ok' in diag && diag.ok ? (
                <div className="dsh-mcs-diag-grid">
                  <div className="dsh-mcs-diag-cell"><span>{t('diagElapsed')}</span><strong>{diag.elapsedMs} ms</strong></div>
                  {diag.protocolVersion !== undefined && <div className="dsh-mcs-diag-cell"><span>{t('diagProtocol')}</span><strong>{diag.protocolVersion}</strong></div>}
                  {diag.serverName !== undefined && <div className="dsh-mcs-diag-cell"><span>{t('diagServer')}</span><strong>{diag.serverName}{diag.serverVersion !== undefined ? ` ${diag.serverVersion}` : ''}</strong></div>}
                  {diag.toolCount !== undefined && <div className="dsh-mcs-diag-cell"><span>{t('diagTools')}</span><strong>{diag.toolCount}</strong></div>}
                </div>
              ) : (
                <div className="dsh-mcs-diag-error">{'error' in diag ? diag.error : 'failed'}</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
