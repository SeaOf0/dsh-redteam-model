/** Shared section shape, schema, and pure helpers. */
import z from '@deepseek-ai/schemastery'
import type { Config as McpClientConfig } from '@deepseek-ai/dsh-mcp-client'

/** Stable row id grammar. */
export const ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/
/** Default per-tool-call timeout passed to the mcp-client bridge (ms). */
export const DEFAULT_TOOL_CALL_TIMEOUT_MS = 60_000

export type Transport = 'stdio' | 'streamable-http'

/** One user-configured MCP server row. */
export interface ServerEntry {
  /** Stable row identity used to diff mounted instances. */
  readonly id: string
  /** Disabled rows are kept in the document but mount nothing. */
  readonly enabled: boolean
  /** Model-facing tool namespace: `mcp__<name>__<tool>`; unique across enabled rows. */
  readonly name: string
  readonly transport: Transport
  /** stdio: executable to spawn. */
  readonly command: string
  /** stdio: one-line argument string (split on whitespace, quotes honored). */
  readonly argsLine: string
  /** stdio: extra environment variables merged over the scrubbed parent env. */
  readonly env: Record<string, string>
  /** stdio: working directory for the child process. */
  readonly cwd: string
  /** streamable-http: MCP endpoint URL. */
  readonly url: string
  /** streamable-http: extra request headers (e.g. Authorization). */
  readonly headers: Record<string, string>
  /** Per-tool-call timeout in milliseconds. */
  readonly toolCallTimeoutMs: number
  /** Reject the mount when the initial connection or tool sync fails. */
  readonly failOnStartupError: boolean
}

/** The whole `mcp-studio` settings section. */
export interface StudioSection {
  readonly servers: ServerEntry[]
}

export const ServerEntrySchema = z.object({
  id: z.string().required().pattern(ID_PATTERN),
  enabled: z.boolean().default(true),
  name: z.string().default(''),
  transport: z.union([z.const('stdio'), z.const('streamable-http')]).default('stdio'),
  command: z.string().default(''),
  argsLine: z.string().default(''),
  env: z.dict(z.string()),
  cwd: z.string().default(''),
  url: z.string().default(''),
  headers: z.dict(z.string()),
  toolCallTimeoutMs: z.number().step(1_000).min(1_000).max(3_600_000).default(DEFAULT_TOOL_CALL_TIMEOUT_MS),
  failOnStartupError: z.boolean().default(false),
}) as unknown as z<ServerEntry>

export const Config = z.object({
  servers: z.array(ServerEntrySchema).default([]),
}) as unknown as z<StudioSection>

/** Split one argument line into argv tokens; single/double quotes and backslash escapes are honored. */
export function splitArgs(line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: "'" | '"' | undefined
  let started = false
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]!
    if (quote === undefined) {
      if (char === ' ' || char === '\t') {
        if (started) {
          tokens.push(current)
          current = ''
          started = false
        }
        continue
      }
      if (char === '\\' && index + 1 < line.length) {
        current += line[++index]!
        started = true
        continue
      }
      if (char === "'" || char === '"') {
        quote = char
        started = true
        continue
      }
      current += char
      started = true
    } else if (quote === "'") {
      if (char === "'") quote = undefined
      else current += char
    } else {
      if (char === '\\' && index + 1 < line.length) {
        current += line[++index]!
      } else if (char === '"') {
        quote = undefined
      } else {
        current += char
      }
    }
  }
  if (started) tokens.push(current)
  return tokens
}

/** Project one server row onto the mcp-client config shape. */
export function toMcpClientConfig(server: ServerEntry): McpClientConfig {
  const base = {
    serverName: server.name,
    toolCallTimeoutMs: server.toolCallTimeoutMs,
    failOnStartupError: server.failOnStartupError,
  }
  if (server.transport === 'stdio') {
    return {
      ...base,
      transport: 'stdio',
      command: server.command,
      args: splitArgs(server.argsLine),
      env: server.env,
      cwd: server.cwd,
    }
  }
  return {
    ...base,
    transport: 'streamable-http',
    url: server.url,
    headers: server.headers,
  }
}

/** Cross-field constraints the schema cannot express; throwing refuses the write. */
export function validateSection(value: StudioSection): void {
  const names = new Set<string>()
  for (const server of value.servers) {
    if (!server.enabled) continue
    if (names.has(server.name)) {
      throw new Error(`mcp-studio: two enabled servers share the name "${server.name}" — server names must be unique`)
    }
    if (server.name.trim() === '') {
      throw new Error(`mcp-studio: an enabled server has no name`)
    }
    names.add(server.name)
    if (server.transport === 'stdio' && server.command.trim() === '') {
      throw new Error(`mcp-studio: stdio server "${server.name}" has no command`)
    }
    if (server.transport === 'streamable-http') {
      if (server.url.trim() === '') throw new Error(`mcp-studio: server "${server.name}" has no url`)
      let parsed: URL
      try {
        parsed = new URL(server.url)
      } catch {
        throw new Error(`mcp-studio: server "${server.name}" url "${server.url}" is not a valid URL`)
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`mcp-studio: server "${server.name}" url must use http or https`)
      }
    }
  }
}
