/** Connection diagnostics: one short-lived MCP handshake (stdio or streamable-http) reporting elapsed time, protocol version, server info, and tool count. */
import { spawn } from 'node:child_process'
import { splitArgs } from './types.ts'
import type { ServerEntry } from './types.ts'

export interface DiagnoseReport {
  readonly ok: boolean
  readonly elapsedMs: number
  readonly protocolVersion?: string
  readonly serverName?: string
  readonly serverVersion?: string
  readonly toolCount?: number
  readonly error?: string
}

const TIMEOUT_MS = 10_000

function line(obj: unknown): string {
  return `${JSON.stringify(obj)}\n`
}

interface MinimalMcp {
  send(payload: string): void
  onMessage(handler: (message: Record<string, unknown>) => void): void
  close(): void
}

function stdioTransport(server: ServerEntry): MinimalMcp {
  const args = splitArgs(server.argsLine)
  const child = spawn(server.command, args, {
    cwd: server.cwd === '' ? undefined : server.cwd,
    env: { ...process.env, ...server.env },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  let buffer = ''
  const listeners: Array<(message: Record<string, unknown>) => void> = []
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (chunk: string) => {
    buffer += chunk
    let nl: number
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const frame = buffer.slice(0, nl).trim()
      buffer = buffer.slice(nl + 1)
      if (frame === '') continue
      try {
        const message = JSON.parse(frame) as Record<string, unknown>
        for (const listener of listeners) listener(message)
      } catch {
        // Non-JSON noise on stdout: ignore.
      }
    }
  })
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', () => {
    // Server logs on stderr are expected; not surfaced here.
  })
  return {
    send: payload => child.stdin.write(payload),
    onMessage: handler => listeners.push(handler),
    close: () => {
      child.kill()
    },
  }
}

async function httpTransport(server: ServerEntry, messages: Array<Record<string, unknown>>): Promise<Array<Record<string, unknown>>> {
  const url = new URL(server.url)
  const responses: Array<Record<string, unknown>> = []
  for (const message of messages) {
    // Notifications carry no id and servers legitimately answer 202/empty —
    // never parse their bodies; only real requests contribute responses.
    const isNotification = typeof message.method === 'string' && message.id === undefined
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...server.headers,
      },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
    if (isNotification) continue
    if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`)
    const contentType = response.headers.get('content-type') ?? ''
    const text = await response.text()
    if (text.trim() === '') throw new Error(`empty response body from ${server.url}`)
    if (contentType.includes('text/event-stream')) {
      for (const frame of text.split('\n')) {
        if (!frame.startsWith('data:')) continue
        const payload = frame.slice(5).trim()
        if (payload === '') continue
        try {
          responses.push(JSON.parse(payload) as Record<string, unknown>)
        } catch {
          // keep scanning frames
        }
      }
    } else {
      responses.push(JSON.parse(text) as Record<string, unknown>)
    }
  }
  return responses
}

/** Run one full handshake: a throwaway stdio child, or initialize + tools/list over HTTP. */
export async function diagnoseServer(server: ServerEntry): Promise<DiagnoseReport> {
  const started = Date.now()
  try {
    if (server.transport === 'streamable-http') {
      const messages = [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'dsh-mcp-studio-diag', version: '0.1.0' } } },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      ]
      const responses = await httpTransport(server, messages)
      const init = responses.find(message => message.id === 1)
      const tools = responses.find(message => message.id === 2)
      if (init === undefined || (init.result === undefined && init.error !== undefined)) {
        throw new Error(`initialize failed: ${JSON.stringify(init?.error ?? 'no response')}`)
      }
      const info = (init.result ?? {}) as Record<string, unknown>
      const serverInfo = (info.serverInfo ?? {}) as Record<string, unknown>
      const toolList = Array.isArray((tools?.result as { tools?: unknown } | undefined)?.tools)
        ? ((tools?.result as { tools: unknown[] }).tools.length)
        : undefined
      return {
        ok: true,
        elapsedMs: Date.now() - started,
        protocolVersion: typeof info.protocolVersion === 'string' ? info.protocolVersion : undefined,
        serverName: typeof serverInfo.name === 'string' ? serverInfo.name : undefined,
        serverVersion: typeof serverInfo.version === 'string' ? serverInfo.version : undefined,
        toolCount: toolList,
      }
    }
    return await new Promise<DiagnoseReport>((resolve, reject) => {
      const transport = stdioTransport(server)
      const timer = setTimeout(() => {
        transport.close()
        reject(new Error(`handshake timed out after ${TIMEOUT_MS}ms`))
      }, TIMEOUT_MS)
      let protocolVersion: string | undefined
      let serverName: string | undefined
      let serverVersion: string | undefined
      let toolCount: number | undefined
      transport.onMessage(message => {
        if (message.id === 1 && message.result !== undefined) {
          const info = message.result as Record<string, unknown>
          const serverInfo = (info.serverInfo ?? {}) as Record<string, unknown>
          protocolVersion = typeof info.protocolVersion === 'string' ? info.protocolVersion : undefined
          serverName = typeof serverInfo.name === 'string' ? serverInfo.name : undefined
          serverVersion = typeof serverInfo.version === 'string' ? serverInfo.version : undefined
          transport.send(line({ jsonrpc: '2.0', method: 'notifications/initialized' }))
          transport.send(line({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }))
        } else if (message.id === 2 && message.result !== undefined) {
          const tools = (message.result as { tools?: unknown }).tools
          toolCount = Array.isArray(tools) ? tools.length : 0
          clearTimeout(timer)
          transport.close()
          resolve({
            ok: true,
            elapsedMs: Date.now() - started,
            ...(protocolVersion === undefined ? {} : { protocolVersion }),
            ...(serverName === undefined ? {} : { serverName }),
            ...(serverVersion === undefined ? {} : { serverVersion }),
            toolCount,
          })
        } else if (message.error !== undefined) {
          clearTimeout(timer)
          transport.close()
          reject(new Error(JSON.stringify(message.error)))
        }
      })
      transport.onMessage(() => {})
      transport.send(line({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'dsh-mcp-studio-diag', version: '0.1.0' } } }))
      // Spawn failures surface as close-before-response.
      // (transport.close in the timer covers hangs; exit events are implicit.)
    })
  } catch (error) {
    return {
      ok: false,
      elapsedMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}
