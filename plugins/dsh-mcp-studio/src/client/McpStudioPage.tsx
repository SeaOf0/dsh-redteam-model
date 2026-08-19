/** The MCP Studio settings page: stats strip, server cards, JSON drawer, filter bar, execution log. */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactElement } from 'react'
import type { DiagnoseReport, ServerLive, StudioLive, Translate } from './contracts.js'
import type { StudioCardFace } from './controller.js'
import { useStoreState } from './components.js'
import { ServerCard } from './ServerCard.js'
import { MCP_JSON_TEMPLATE, formatMcpJson, serversToMcpJson } from './mcp-json.js'
import { SERVER_PRESETS } from './presets.js'

const STATUS_POLL_MS = 3_000

type StatusFilter = 'all' | 'connected' | 'down' | 'disabled'

const FILTER_CLASS: Record<StatusFilter, string> = {
  all: '',
  connected: 'dsh-mcs-state--ok',
  down: 'dsh-mcs-state--busy',
  disabled: 'dsh-mcs-state--off',
}

function matchesStatusFilter(state: ServerLive['state'], filter: StatusFilter): boolean {
  if (filter === 'all') return true
  if (filter === 'connected') return state === 'connected'
  if (filter === 'disabled') return state === 'disabled'
  return state === 'mounting' || state === 'unreachable' || state === 'error'
}

export function createStudioPage(face: StudioCardFace, t: Translate, pollStatus: () => Promise<StudioLive | { error: string }>, diagnose?: (id: string) => Promise<DiagnoseReport | { error: string }>, clearExecutions?: () => Promise<{ cleared: boolean } | { error: string }>): () => ReactElement {
  return function McpStudioPage(): ReactElement {
    const state = useStoreState(face.hooks.studio)
    // Cards are collapsed by default; only rows created via 添加服务器 expand.
    const [openIds, setOpenIds] = useState<Set<string>>(() => new Set())
    const [live, setLive] = useState<StudioLive | undefined>(undefined)
    const [pasteOpen, setPasteOpen] = useState(false)
    const [pasteText, setPasteText] = useState('')
    const [templateFilled, setTemplateFilled] = useState(false)
    const [pasteNote, setPasteNote] = useState<{ kind: 'ok' | 'err'; text: string } | undefined>(undefined)
    const [filterText, setFilterText] = useState('')
    const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
    const [compact, setCompact] = useState(false)
    const [draggingId, setDraggingId] = useState<string | undefined>(undefined)
    const [overId, setOverId] = useState<string | undefined>(undefined)
    const [execPage, setExecPage] = useState(0)
    const [execServerFilter, setExecServerFilter] = useState('')
    const [confirmClear, setConfirmClear] = useState(false)

    // Live status: poll while the page is mounted; each poll is one cheap RPC.
    useEffect(() => {
      let alive = true
      const tick = async (): Promise<void> => {
        const result = await pollStatus()
        if (alive && !('error' in result)) setLive(result)
      }
      void tick()
      const timer = setInterval(() => { void tick() }, STATUS_POLL_MS)
      return () => {
        alive = false
        clearInterval(timer)
      }
    }, [pollStatus])

    const toggle = useCallback((id: string) => {
      setOpenIds(current => {
        const next = new Set(current)
        if (next.has(id)) next.delete(id)
        else next.add(id)
        return next
      })
    }, [])

    const addServer = useCallback(() => {
      face.addServer()
    }, [face])

    const openDrawer = useCallback((prefill?: string) => {
      if (prefill !== undefined) setPasteText(prefill)
      else if (!templateFilled && pasteText.trim() === '') {
        setPasteText(MCP_JSON_TEMPLATE)
        setTemplateFilled(true)
      }
      setPasteOpen(true)
    }, [pasteText, templateFilled])

    const runFormat = useCallback(() => {
      const result = formatMcpJson(pasteText)
      if ('error' in result) {
        setPasteNote({ kind: 'err', text: result.error })
        return
      }
      setPasteText(result.text)
      setPasteNote(undefined)
    }, [pasteText])

    const runJsonImport = useCallback(() => {
      const result = face.importMcpJson(pasteText)
      if ('error' in result) {
        setPasteNote({ kind: 'err', text: result.error })
        return
      }
      setPasteOpen(false)
      setPasteText('')
      setPasteNote({ kind: 'ok', text: `${t('importDone')} ${result.servers}${result.warnings.length > 0 ? ` · ${result.warnings.join('；')}` : ''}` })
    }, [face, pasteText, t])

    const copyAll = useCallback(() => {
      const json = serversToMcpJson(state.view.servers)
      void navigator.clipboard?.writeText(json).then(
        () => setPasteNote({ kind: 'ok', text: t('copiedAll') }),
        () => openDrawer(json),
      )
    }, [state.view.servers, t, openDrawer])

    const liveById = useMemo(() => new Map<string, ServerLive>((live?.servers ?? []).map(server => [server.id, server])), [live])

    const visibleServers = useMemo(() => {
      const needle = filterText.trim().toLowerCase()
      return state.view.servers.filter(server => {
        if (statusFilter !== 'all') {
          const serverState = liveById.get(server.id)?.state ?? (server.enabled ? 'mounting' : 'disabled')
          if (!matchesStatusFilter(serverState, statusFilter)) return false
        }
        if (needle === '') return true
        return server.name.toLowerCase().includes(needle)
          || server.command.toLowerCase().includes(needle)
          || server.url.toLowerCase().includes(needle)
          || server.argsLine.toLowerCase().includes(needle)
      })
    }, [state.view.servers, filterText, statusFilter, liveById])

    const formatTime = (at: number): string => {
      const date = new Date(at)
      const pad = (value: number): string => String(value).padStart(2, '0')
      return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
    }

    if (state.status === 'loading') {
      return <div className="dsh-mcs"><span className="dsh-mcs-spin" /> {t('loading')}</div>
    }
    if (state.status !== 'ready') {
      return <div className="dsh-mcs">{t('readOnly')}</div>
    }

    const canSave = state.dirty && !state.saving && state.errors.length === 0 && state.writable

    return (
      <div className={compact ? 'dsh-mcs dsh-mcs--compact' : 'dsh-mcs'}>
        <div className="dsh-mcs-head">
          <div>
            <h2 className="dsh-mcs-title">{t('title')}</h2>
            <p className="dsh-mcs-sub">{t('subtitle')}</p>
          </div>
          <div className="dsh-mcs-toolbar">
            {state.dirty && <span className="dsh-mcs-dirty">{t('unsaved')}</span>}
            {state.failed && <span className="dsh-mcs-failed">{t('saveFailed')}</span>}
            <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={() => setCompact(value => !value)}>
              {compact ? t('comfortable') : t('compact')}
            </button>
            <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={() => { if (pasteOpen) setPasteOpen(false); else openDrawer() }}>
              {t('pasteJson')}
            </button>
            {state.view.servers.length > 0 && (
              <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={copyAll}>
                {t('copyJson')}
              </button>
            )}
            <button type="button" className="dsh-mcs-btn dsh-mcs-btn--primary" disabled={state.saving} onClick={addServer}>
              {t('addServer')}
            </button>
            <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" disabled={!state.dirty || state.saving} onClick={() => face.discard()}>
              {t('discard')}
            </button>
            <button type="button" className="dsh-mcs-btn dsh-mcs-btn--primary" disabled={!canSave} onClick={() => void face.save()}>
              {t('save')}
            </button>
          </div>
        </div>

        <div className="dsh-mcs-stats">
          <div className="dsh-mcs-stat"><span>{t('statTotal')}</span><strong>{live?.summary.total ?? state.view.servers.length}</strong></div>
          <div className="dsh-mcs-stat"><span>{t('statEnabled')}</span><strong>{live?.summary.enabled ?? state.view.servers.filter(server => server.enabled).length}</strong></div>
          <div className="dsh-mcs-stat dsh-mcs-stat--ok"><span>{t('statConnected')}</span><strong>{live?.summary.connected ?? 0}</strong></div>
          <div className="dsh-mcs-stat dsh-mcs-stat--accent"><span>{t('statTools')}</span><strong>{live?.summary.tools ?? 0}</strong></div>
        </div>

        {pasteOpen && (
          <div className="dsh-mcs-drawer">
            <div className="dsh-mcs-drawer-inner">
              <small style={{ color: 'var(--dsw-alias-label-secondary)' }}>{t('pasteJsonHint')}</small>
              <div className="dsh-mcs-presets">
                {SERVER_PRESETS.map(preset => (
                  <button
                    key={preset.id}
                    type="button"
                    className="dsh-mcs-preset"
                    title={preset.description}
                    onClick={() => {
                      setPasteText(preset.json)
                      setTemplateFilled(true)
                      setPasteNote(undefined)
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <textarea
                className="dsh-mcs-json"
                rows={7}
                spellCheck={false}
                placeholder={t('pasteJsonPlaceholder')}
                value={pasteText}
                onChange={event => setPasteText(event.target.value)}
              />
              <div className="dsh-mcs-toolbar">
                <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={() => { setPasteText(MCP_JSON_TEMPLATE); setTemplateFilled(true); setPasteNote(undefined) }}>
                  {t('fillTemplate')}
                </button>
                <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" disabled={pasteText.trim() === ''} onClick={runFormat}>
                  {t('formatJson')}
                </button>
                <span style={{ flex: 1 }} />
                <button type="button" className="dsh-mcs-btn dsh-mcs-btn--primary" disabled={pasteText.trim() === ''} onClick={runJsonImport}>
                  {t('importJson')}
                </button>
              </div>
            </div>
          </div>
        )}
        {pasteNote !== undefined && (
          <div className={pasteNote.kind === 'ok' ? 'dsh-mcs-sub' : 'dsh-mcs-errors'} style={pasteNote.kind === 'ok' ? undefined : { padding: '6px 10px' }}>
            {pasteNote.text}
          </div>
        )}

        {!state.writable && <p className="dsh-mcs-sub">{t('readOnly')}</p>}
        {state.errors.length > 0 && (
          <div className="dsh-mcs-errors">
            <strong>{t('errorsHeader')}</strong>
          </div>
        )}

        {state.view.servers.length > 0 && (
          <div className="dsh-mcs-filterbar">
            <input
              className="dsh-mcs-search"
              style={{ maxWidth: 260 }}
              placeholder={t('filterServers')}
              value={filterText}
              onChange={event => setFilterText(event.target.value)}
            />
            <div className="dsh-mcs-seg">
              {(['all', 'connected', 'down', 'disabled'] as const).map(filter => (
                <button
                  key={filter}
                  type="button"
                  className={statusFilter === filter ? 'is-on' : undefined}
                  aria-pressed={statusFilter === filter}
                  onClick={() => setStatusFilter(filter)}
                >
                  <span className={FILTER_CLASS[filter]}>{t(`filter_${filter}` as never)}</span>
                </button>
              ))}
            </div>
            {visibleServers.length !== state.view.servers.length && (
              <span className="dsh-mcs-sub" style={{ margin: 0 }}>{visibleServers.length} / {state.view.servers.length}</span>
            )}
          </div>
        )}

        {state.view.servers.length === 0 ? (
          <div className="dsh-mcs-empty">
            <p>{t('empty')}</p>
            <div className="dsh-mcs-toolbar" style={{ justifyContent: 'center' }}>
              <button type="button" className="dsh-mcs-btn dsh-mcs-btn--primary" disabled={state.saving} onClick={addServer}>
                {t('addServer')}
              </button>
              <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={() => openDrawer()}>
                {t('pasteJson')}
              </button>
            </div>
          </div>
        ) : visibleServers.map(server => (
          <div
            key={server.id}
            draggable={!openIds.has(server.id)}
            onDragStart={event => {
              setDraggingId(server.id)
              event.dataTransfer.effectAllowed = 'move'
              event.dataTransfer.setData('text/plain', server.id)
            }}
            onDragEnd={() => {
              setDraggingId(undefined)
              setOverId(undefined)
            }}
            onDragOver={event => {
              if (draggingId === undefined || draggingId === server.id) return
              event.preventDefault()
              event.dataTransfer.dropEffect = 'move'
              setOverId(server.id)
            }}
            onDragLeave={() => setOverId(current => current === server.id ? undefined : current)}
            onDrop={event => {
              event.preventDefault()
              const dragged = draggingId ?? event.dataTransfer.getData('text/plain')
              if (dragged !== '' && dragged !== server.id) face.moveServer(dragged, server.id)
              setDraggingId(undefined)
              setOverId(undefined)
            }}
            className={draggingId === server.id ? 'dsh-mcs-drag' : undefined}
            data-droptarget={overId === server.id ? '1' : undefined}
          >
            <ServerCard
              server={server}
              live={liveById.get(server.id)}
              open={openIds.has(server.id)}
              onToggle={() => toggle(server.id)}
              t={t}
              disabled={state.saving}
              onUpdate={next => face.updateServerDraft(next)}
              onRemove={() => face.removeServer(server.id)}
              diagnose={diagnose}
            />
          </div>
        ))}

        {(live?.executions?.length ?? 0) > 0 && (() => {
          const records = (live!.executions ?? []).filter(record => execServerFilter === '' || record.server === execServerFilter)
          const capacity = live?.execCapacity ?? 200
          const pageSize = 20
          const pageCount = Math.max(1, Math.ceil(records.length / pageSize))
          const page = Math.min(execPage, pageCount - 1)
          const rows = records.slice(page * pageSize, page * pageSize + pageSize)
          const servers = [...new Set((live!.executions ?? []).map(record => record.server))].sort()
          return (
            <div className="dsh-mcs-exec">
              <div className="dsh-mcs-exec-head">
                <h4 className="dsh-mcs-exec-title">{t('execTitle')} ({records.length}/{capacity})</h4>
                {servers.length > 1 && (
                  <select
                    className="dsh-mcs-search"
                    style={{ maxWidth: 160 }}
                    value={execServerFilter}
                    onChange={event => {
                      setExecServerFilter(event.target.value)
                      setExecPage(0)
                    }}
                  >
                    <option value="">{t('execAllServers')}</option>
                    {servers.map(server => <option key={server} value={server}>{server}</option>)}
                  </select>
                )}
                <span style={{ flex: 1 }} />
                {clearExecutions !== undefined && (
                  <button
                    type="button"
                    className={confirmClear ? 'dsh-mcs-btn dsh-mcs-btn--danger2' : 'dsh-mcs-btn dsh-mcs-btn--ghost'}
                    onClick={() => {
                      if (!confirmClear) {
                        setConfirmClear(true)
                        setTimeout(() => setConfirmClear(false), 3000)
                        return
                      }
                      setConfirmClear(false)
                      void clearExecutions().then(() => setExecPage(0))
                    }}
                  >
                    {confirmClear ? t('execConfirmClear') : t('execClear')}
                  </button>
                )}
              </div>
              <table className="dsh-mcs-exectable">
                <thead>
                  <tr>
                    <th>{t('execTime')}</th>
                    <th>{t('execServer')}</th>
                    <th>{t('execTool')}</th>
                    <th>{t('execDuration')}</th>
                    <th>{t('execStatus')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((record, index) => (
                    <tr key={index}>
                      <td>{formatTime(record.at)}</td>
                      <td>{record.server}</td>
                      <td><code>{record.tool}</code></td>
                      <td>{record.durationMs} ms</td>
                      <td>
                        {record.ok
                          ? <span className="dsh-mcs-exec-ok">{t('execOk')}</span>
                          : <span className="dsh-mcs-exec-err" title={record.error ?? ''}>{t('execFailed')}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="dsh-mcs-exec-foot">
                <small className="dsh-mcs-sub" style={{ margin: 0 }}>{t('execMemoryHint', { capacity })}</small>
                {pageCount > 1 && (
                  <div className="dsh-mcs-pager">
                    <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" disabled={page === 0} onClick={() => setExecPage(page - 1)}>‹</button>
                    <span>{page + 1} / {pageCount}</span>
                    <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" disabled={page >= pageCount - 1} onClick={() => setExecPage(page + 1)}>›</button>
                  </div>
                )}
              </div>
            </div>
          )
        })()}

      </div>
    )
  }
}
