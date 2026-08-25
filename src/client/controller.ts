/**
 * Thin RPC client for the dsh-redteam-model management section.
 *
 * Wraps the host loopback connection in a small AdminFace. Every call throws
 * a readable, prefixed error when the host rejects it.
 */
import {
  CHANNEL,
  type AdminClearResult,
  type AdminConnectionHandle,
  type AdminOperationCancelResult,
  type AdminOperationStart,
  type AdminOperationStartResult,
  type AdminStatus,
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

export class AdminController {
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
    const result = await this.connection.rpc.call(CHANNEL, endpoint, payload)
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
