/** MCP config JSON parser and exporter: accepts {"mcpServers":…} / {"servers":…} / bare maps / single-server objects / one wrapper level; non-server metadata keys are ignored. */
import type { ServerDraft } from './contracts.js'

export interface McpJsonParseResult {
  readonly servers: ServerDraft[]
  readonly warnings: string[]
}

const DEFAULT_TIMEOUT_MS = 60_000

function quoteArg(token: string): string {
  if (token === '') return '""'
  if (!/[\s"']/.test(token)) return token
  return `"${token.replace(/(["\\])/g, '\\$1')}"`
}

/** args array → one argsLine the user can keep editing (quotes preserved). */
export function argsToLine(args: readonly unknown[]): string {
  return args.filter(arg => typeof arg === 'string').map(arg => quoteArg(arg as string)).join(' ')
}

function toPairs(value: unknown): Array<{ key: string; value: string }> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return []
  return Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
    .map(([key, v]) => ({ key, value: String(v) }))
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/** Parse one server config object into a draft; undefined when it is not a server. */
function parseServerEntry(name: string, raw: unknown): ServerDraft | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined
  const entry = raw as Record<string, unknown>
  const declared = str(entry.type).toLowerCase()
  const args = Array.isArray(entry.args) ? entry.args : []
  const command = str(entry.command)
  const url = str(entry.url)
  const isHttp = declared === 'http' || declared === 'sse' || declared === 'streamable-http'
    || (command === '' && url !== '')
  if (!isHttp && command === '') return undefined
  return {
    id: '',
    enabled: entry.disabled !== true,
    name,
    transport: isHttp ? 'streamable-http' : 'stdio',
    command: isHttp ? '' : command,
    argsLine: isHttp ? '' : argsToLine(args),
    env: isHttp ? [] : toPairs(entry.env),
    cwd: isHttp ? '' : str(entry.cwd),
    url: isHttp ? url : '',
    headers: isHttp ? toPairs(entry.headers) : [],
    toolCallTimeoutMs: DEFAULT_TIMEOUT_MS,
    failOnStartupError: false,
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Built-in starter template pre-filled into the paste drawer. */
export const MCP_JSON_TEMPLATE = `{
  "mcpServers": {
    "example": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"],
      "env": {}
    }
  }
}`

/**
 * Pretty-print any pasted config (two-space indent); returns an error for invalid JSON.
 */
export function formatMcpJson(text: string): { text: string } | { error: string } {
  const trimmed = text.trim()
  if (trimmed === '') return { error: 'empty input' }
  try {
    const document: unknown = JSON.parse(trimmed)
    return { text: `${JSON.stringify(document, null, 2)}\n` }
  } catch (error) {
    return { error: `invalid JSON: ${error instanceof Error ? error.message : String(error)}` }
  }
}

/** argsLine → argv array (whitespace split, quotes honored). */
export function lineToArgs(line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: string | undefined
  let started = false
  for (const char of line) {
    if (quote === undefined) {
      if (char === ' ' || char === '\t') {
        if (started) {
          tokens.push(current)
          current = ''
          started = false
        }
        continue
      }
      if (char === '"' || char === "'") {
        quote = char
        started = true
        continue
      }
      current += char
      started = true
    } else if (char === quote) {
      quote = undefined
    } else {
      current += char
    }
  }
  if (started) tokens.push(current)
  return tokens
}

function pairsToRecord(pairs: ReadonlyArray<{ key: string; value: string }>): Record<string, string> {
  const record: Record<string, string> = {}
  for (const pair of pairs) {
    if (pair.key.trim() !== '') record[pair.key] = pair.value
  }
  return record
}

/** Project drafts back onto the Claude Desktop `mcpServers` JSON shape (export path). */
export function serversToMcpJson(servers: ReadonlyArray<{
  name: string
  transport: 'stdio' | 'streamable-http'
  command: string
  argsLine: string
  env: ReadonlyArray<{ key: string; value: string }>
  cwd: string
  url: string
  headers: ReadonlyArray<{ key: string; value: string }>
}>): string {
  const mcpServers: Record<string, Record<string, unknown>> = {}
  for (const server of servers) {
    mcpServers[server.name] = server.transport === 'stdio'
      ? {
        command: server.command,
        ...(server.argsLine.trim() === '' ? {} : { args: lineToArgs(server.argsLine) }),
        ...(Object.keys(pairsToRecord(server.env)).length === 0 ? {} : { env: pairsToRecord(server.env) }),
        ...(server.cwd.trim() === '' ? {} : { cwd: server.cwd }),
      }
      : {
        type: 'http',
        url: server.url,
        ...(Object.keys(pairsToRecord(server.headers)).length === 0 ? {} : { headers: pairsToRecord(server.headers) }),
      }
  }
  return `${JSON.stringify({ mcpServers }, null, 2)}\n`
}

/** Parse a pasted JSON document into server drafts; names deduplicate with suffixes. */
export function parseMcpJson(text: string, existing: Readonly<Iterable<string>> = []): McpJsonParseResult | { error: string } {
  const trimmed = text.trim()
  if (trimmed === '') return { error: 'empty input' }
  let document: unknown
  try {
    document = JSON.parse(trimmed)
  } catch (error) {
    return { error: `invalid JSON: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!isObject(document)) return { error: 'expected a JSON object' }
  const warnings: string[] = []
  const collect = (map: Record<string, unknown>): ServerDraft[] => {
    const servers: ServerDraft[] = []
    for (const [rawName, rawEntry] of Object.entries(map)) {
      // Scalar/array values can never be server entries — metadata or a
      // single server's own fields leaking to map level: ignore quietly.
      if (!isObject(rawEntry)) continue
      if (rawName === '_meta' || rawName === 'inputs' || rawName.startsWith('$')) continue
      const draft = parseServerEntry(rawName, rawEntry)
      if (draft === undefined) {
        warnings.push(`skipped "${rawName}": no command (stdio) or url (http)`)
        continue
      }
      servers.push(draft)
    }
    return servers
  }
  const resolveMap = (value: Record<string, unknown>): ServerDraft[] | undefined => {
    const container = value.mcpServers ?? value.servers
    if (isObject(container)) return collect(container)
    const single = parseServerEntry('', value)
    if (single !== undefined) return [single]
    const bare = collect(value)
    if (bare.length > 0) return bare
    const children = Object.values(value).filter(isObject)
    if (children.length === 1) {
      const nested = resolveMap(children[0]!)
      if (nested !== undefined && nested.length > 0) return nested
    }
    return undefined
  }
  let servers: ServerDraft[] | undefined
  try {
    servers = resolveMap(document)
  } catch {
    servers = undefined
  }
  if (servers === undefined || servers.length === 0) {
    return {
      error: warnings[0]
        ?? 'no server entries found: expected {"mcpServers": {...}}, {"servers": {...}}, a bare {name: config} map, or one server object',
    }
  }
  const used = new Set<string>(existing)
  const uniqueName = (wanted: string): string => {
    let base = wanted === '' ? 'server' : wanted.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 32)
    if (base === '') base = 'server'
    if (!used.has(base)) {
      used.add(base)
      return base
    }
    let n = 2
    while (used.has(`${base}-${n}`)) n += 1
    base = `${base}-${n}`
    used.add(base)
    return base
  }
  return { servers: servers.map(server => ({ ...server, name: uniqueName(server.name) })), warnings }
}
