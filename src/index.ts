/**
 * dsh-redteam-model management host plugin.
 *
 * The plugin itself never installs modes or sub-plugins at startup; all
 * mutations are triggered by the settings page through the loopback RPC.
 */

import { OperationQueue } from './operations.ts'
import { registerModelRpc } from './rpc.ts'
import type { HostConnectionHandle } from './types.ts'

export const name = 'dsh-redteam-model'
export const inject = ['connection']

/** Minimal structural face of the Cordis context this plugin needs. */
export interface HostContext {
  inject(services: readonly string[], callback: (services: Record<string, unknown>) => void): unknown
  effect(cleanup: () => void | (() => void), label?: string): unknown
}

export function apply(ctx: HostContext): void {
  const queue = new OperationQueue()

  ctx.inject(['connection'], (web: Record<string, unknown>) => {
    const { connection } = web as { connection: HostConnectionHandle }
    registerModelRpc(connection, queue)
  })

  ctx.effect(() => () => {
    queue.dispose()
  }, 'dsh-redteam-model: queue')
}
