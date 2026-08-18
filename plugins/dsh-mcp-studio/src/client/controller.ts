/** Staged form controller: edits stage a replacement section; Save writes it through the scope. */
import type { DraftError, ServerDraft, SettingsScope, StudioDraft } from './contracts.js'
import { createStore, type WritableStore } from './store.js'
import { parseMcpJson } from './mcp-json.js'

const ID_RE = /^[A-Za-z0-9_-]{1,32}$/
const NAME_RE = /^[A-Za-z0-9_-]{1,32}$/

export interface StudioCardState {
  status: 'loading' | 'ready' | 'unavailable'
  writable: boolean
  view: StudioDraft
  dirty: boolean
  saving: boolean
  failed: boolean
  errors: DraftError[]
}

export interface StudioCardActions {
  addServer(): string
  updateServerDraft(next: ServerDraft): void
  removeServer(id: string): void
  importMcpJson(text: string): { servers: number; warnings: string[] } | { error: string }
  moveServer(id: string, targetId: string): void
  save(): Promise<void>
  discard(): void
}

export interface StudioCardFace extends StudioCardActions {
  hooks: { studio: WritableStore<StudioCardState> }
}

function pairsToDict(pairs: Array<{ key: string; value: string }>): Record<string, string> {
  const dict: Record<string, string> = {}
  for (const pair of pairs) {
    const key = pair.key.trim()
    if (key !== '') dict[key] = pair.value
  }
  return dict
}

function dictToPairs(dict: unknown): Array<{ key: string; value: string }> {
  if (typeof dict !== 'object' || dict === null || Array.isArray(dict)) return []
  return Object.entries(dict as Record<string, unknown>).map(([key, value]) => ({
    key,
    value: typeof value === 'string' ? value : '',
  }))
}

function serverToDraft(raw: unknown): ServerDraft {
  const server = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  return {
    id: typeof server.id === 'string' ? server.id : '',
    enabled: server.enabled !== false,
    name: typeof server.name === 'string' ? server.name : '',
    transport: server.transport === 'streamable-http' ? 'streamable-http' : 'stdio',
    command: typeof server.command === 'string' ? server.command : '',
    argsLine: typeof server.argsLine === 'string' ? server.argsLine : '',
    env: dictToPairs(server.env),
    cwd: typeof server.cwd === 'string' ? server.cwd : '',
    url: typeof server.url === 'string' ? server.url : '',
    headers: dictToPairs(server.headers),
    toolCallTimeoutMs: typeof server.toolCallTimeoutMs === 'number' ? server.toolCallTimeoutMs : 60_000,
    failOnStartupError: server.failOnStartupError === true,
  }
}

export function sectionToDraft(section: unknown): StudioDraft {
  const raw = (typeof section === 'object' && section !== null ? section : {}) as Record<string, unknown>
  const servers = Array.isArray(raw.servers) ? raw.servers.map(serverToDraft) : []
  return { servers }
}

function draftToSection(draft: StudioDraft): { servers: unknown[] } {
  return {
    servers: draft.servers.map(server => ({
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
      failOnStartupError: server.failOnStartupError,
    })),
  }
}

/** Client mirror of the Host cross-field validator. */
export function validateDraft(section: StudioDraft): DraftError[] {
  const errors: DraftError[] = []
  const names = new Set<string>()
  for (const server of section.servers) {
    if (server.name !== '' && !NAME_RE.test(server.name)) {
      errors.push(`server name "${server.name}" must match [A-Za-z0-9_-]{1,32}`)
    }
    if (!server.enabled) continue
    if (server.name === '') errors.push('an enabled server has no name')
    else if (names.has(server.name)) errors.push(`two enabled servers share the name "${server.name}"`)
    if (server.name !== '') names.add(server.name)
    if (server.transport === 'stdio') {
      if (server.command.trim() === '') errors.push(`stdio server "${server.name || '(unnamed)'}" needs a command`)
    } else {
      if (server.url.trim() === '') {
        errors.push(`server "${server.name || '(unnamed)'}" needs a url`)
      } else {
        let parsed: URL | undefined
        try {
          parsed = new URL(server.url)
        } catch {
          parsed = undefined
        }
        if (parsed === undefined) errors.push(`server "${server.name}" url is not valid`)
        else if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          errors.push(`server "${server.name}" url must use http or https`)
        }
      }
    }
  }
  return errors
}

export class StudioController {
  private readonly store: WritableStore<StudioCardState>
  private staged: StudioDraft | undefined
  private saving = false
  private failed = false

  constructor(private readonly scope: SettingsScope) {
    this.store = createStore(this.projection())
    this.scope.subscribe(() => this.publish())
  }

  getStore(): WritableStore<StudioCardState> {
    return this.store
  }

  private currentDraft(): StudioDraft {
    if (this.staged !== undefined) return this.staged
    return sectionToDraft(this.scope.getSnapshot().value)
  }

  private projection(): StudioCardState {
    const snapshot = this.scope.getSnapshot()
    const staged = this.staged
    const view = staged !== undefined ? staged : this.currentDraft()
    const errors = staged !== undefined ? validateDraft(staged) : []
    const dirty = staged !== undefined
      && JSON.stringify(draftToSection(staged)) !== JSON.stringify(draftToSection(sectionToDraft(snapshot.value)))
    return {
      status: snapshot.status,
      writable: snapshot.writable,
      view,
      dirty,
      saving: this.saving,
      failed: this.failed,
      errors,
    }
  }

  private publish(): void {
    this.store.set(this.projection())
  }

  /** Adds a blank row and returns its id (the page expands only these). */
  addServer(): string {
    const base = this.currentDraft()
    const used = new Set(base.servers.map(server => server.id))
    const names = new Set(base.servers.map(server => server.name))
    let id = `srv-${Date.now().toString(36)}`
    while (used.has(id)) id = `${id}x`
    let number = base.servers.length + 1
    let name = `server-${number}`
    while (names.has(name)) {
      number += 1
      name = `server-${number}`
    }
    this.staged = {
      ...base,
      servers: [...base.servers, {
        id,
        enabled: true,
        name,
        transport: 'stdio',
        command: '',
        argsLine: '',
        env: [],
        cwd: '',
        url: '',
        headers: [],
        toolCallTimeoutMs: 60_000,
        failOnStartupError: false,
      }],
    }
    this.failed = false
    this.publish()
    return id
  }

  updateServerDraft(next: ServerDraft): void {
    const base = this.currentDraft()
    this.staged = {
      ...base,
      servers: base.servers.map(server => server.id === next.id ? next : server),
    }
    this.failed = false
    this.publish()
  }

  removeServer(id: string): void {
    const base = this.currentDraft()
    this.staged = { ...base, servers: base.servers.filter(server => server.id !== id) }
    this.failed = false
    this.publish()
  }

  /** Parse pasted MCP-client JSON and stage every server entry as a new row. */
  importMcpJson(text: string): { servers: number; warnings: string[] } | { error: string } {
    const base = this.currentDraft()
    const result = parseMcpJson(text, base.servers.map(server => server.name))
    if ('error' in result) return { error: result.error }
    const used = new Set(base.servers.map(server => server.id))
    const rows = result.servers.map((server, index) => {
      let id = `srv-${Date.now().toString(36)}-${index}`
      while (used.has(id)) id = `${id}x`
      return { ...server, id }
    })
    this.staged = { ...base, servers: [...base.servers, ...rows] }
    this.failed = false
    this.publish()
    return { servers: rows.length, warnings: result.warnings }
  }

  /** Reorder: move `id` directly before `targetId` in the staged draft. */
  moveServer(id: string, targetId: string): void {
    if (id === targetId) return
    const base = this.currentDraft()
    const from = base.servers.findIndex(server => server.id === id)
    const to = base.servers.findIndex(server => server.id === targetId)
    if (from < 0 || to < 0) return
    const servers = [...base.servers]
    const [moved] = servers.splice(from, 1)
    servers.splice(to, 0, moved!)
    this.staged = { ...base, servers }
    this.failed = false
    this.publish()
  }

  async save(): Promise<void> {
    const staged = this.staged
    const snapshot = this.scope.getSnapshot()
    if (staged === undefined || this.saving || snapshot.status !== 'ready') return
    if (validateDraft(staged).length > 0) return
    this.saving = true
    this.failed = false
    this.publish()
    try {
      const wire = draftToSection(staged)
      const stored = draftToSection(sectionToDraft(snapshot.value))
      if (JSON.stringify(wire.servers) !== JSON.stringify(stored.servers)) {
        await this.scope.set('servers', wire.servers)
      }
      this.staged = undefined
    } catch (error) {
      console.warn('[dsh-mcp-studio] save failed', error)
      this.failed = true
    } finally {
      this.saving = false
      this.publish()
    }
  }

  discard(): void {
    this.staged = undefined
    this.failed = false
    this.publish()
  }

  inject(): StudioCardFace {
    return {
      hooks: { studio: this.store },
      addServer: () => this.addServer(),
      updateServerDraft: next => this.updateServerDraft(next),
      removeServer: id => this.removeServer(id),
      importMcpJson: text => this.importMcpJson(text),
      moveServer: (id, targetId) => this.moveServer(id, targetId),
      save: () => this.save(),
      discard: () => this.discard(),
    }
  }
}
