/**
 * Thin RPC client for the dsh-redteam-model management section.
 *
 * Wraps the host loopback connection in a small AdminFace. Every call throws
 * a readable, prefixed error when the host rejects it.
 */
import {
  type AdminClearResult,
  type AdminConnectionHandle,
  type AdminOperationCancelResult,
  type AdminOperationStart,
  type AdminOperationStartResult,
  type AdminStatus,
  type HubRpcResult,
} from './contracts.js'

export interface AdminFace {
  status(): Promise<AdminStatus>
  start(request: AdminOperationStart): Promise<AdminOperationStartResult>
  cancel(id: string): Promise<AdminOperationCancelResult>
  clear(): Promise<AdminClearResult>
}

function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error)
}

/** Modern channel (Host 0.1.2+) served by exact Fetch routes under /api. */
const API_CHANNEL = '/api/dsh-redteam-model'
/** Legacy channel (Host 0.1.1 and older) served by the bare rpc channel. */
const LEGACY_CHANNEL = '/dsh-redteam-model'

export class AdminController {
  private channel: string | null = null
  private legacyTried = false
  private rpcId = 0

  constructor(private readonly connection: AdminConnectionHandle) {}

  async status(): Promise<AdminStatus> {
    return this.call<AdminStatus>('status', {})
  }

  async start(request: AdminOperationStart): Promise<AdminOperationStartResult> {
    return this.call<AdminOperationStartResult>('operation/start', request)
  }

  async cancel(id: string): Promise<AdminOperationCancelResult> {
    return this.call<AdminOperationCancelResult>('operation/cancel', { id })
  }

  async clear(): Promise<AdminClearResult> {
    return this.call<AdminClearResult>('operations/clear', {})
  }

  inject(): AdminFace {
    return {
      status: () => this.status(),
      start: request => this.start(request),
      cancel: id => this.cancel(id),
      clear: () => this.clear(),
    }
  }

  private async call<T>(endpoint: string, payload: unknown): Promise<T> {
    // The modern /api spelling nests below the reserved channel grammar, so it
    // cannot travel through rpc.call — fetch it directly. Legacy Hosts have no
    // /api route for this plugin: fall back once to the bare channel, then
    // stick with whichever transport answered.
    if (this.channel === null) this.channel = API_CHANNEL
    if (this.channel === API_CHANNEL) {
      try {
        return await this.invokeApi<T>(endpoint, payload)
      } catch {
        if (this.legacyTried) throw new Error(`[dsh-redteam-model] ${endpoint} failed: modern /api channel unavailable`)
        this.legacyTried = true
        this.channel = LEGACY_CHANNEL
      }
    }
    return this.invokeLegacy<T>(endpoint, payload)
  }

  private async invokeApi<T>(endpoint: string, payload: unknown): Promise<T> {
    const response = await fetch(`${API_CHANNEL}/${endpoint}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId: `admin-${++this.rpcId}`, method: endpoint, payload }),
    })
    if (!response.ok) throw new Error(`transport failure for ${API_CHANNEL}/${endpoint}: HTTP ${response.status}`)
    const envelope = await response.json() as { type?: string; result?: HubRpcResult }
    if (envelope.type !== 'server-response' || envelope.result === undefined) {
      throw new Error(`transport failure for ${API_CHANNEL}/${endpoint}: malformed envelope`)
    }
    return this.unwrap<T>(endpoint, envelope.result)
  }

  private async invokeLegacy<T>(endpoint: string, payload: unknown): Promise<T> {
    const result = await this.connection.rpc.call(LEGACY_CHANNEL, endpoint, payload)
    return this.unwrap<T>(endpoint, result)
  }

  private unwrap<T>(endpoint: string, result: HubRpcResult): T {
    if (result.ok !== true) {
      const detail = result.error?.message ?? 'unknown error'
      throw new Error(`[dsh-redteam-model] ${endpoint} failed: ${detail}`)
    }
    return result.value as T
  }
}

export function errorMessage(error: unknown): string {
  return messageOf(error)
}
