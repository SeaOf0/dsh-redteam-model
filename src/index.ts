/**
 * dsh-redteam-model management host plugin.
 *
 * The plugin itself never installs modes or sub-plugins at startup; all
 * mutations are triggered by the settings page through the loopback RPC.
 */

import path from 'node:path'

import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
} from './conversationViewSettings.ts'
import { deployGlobalAgents, deployModes, dshHome, getStatus, installOne, profileWebDir, repairMode, scanModes, scanPlugins, uninstallOne } from './manager.ts'
import { OperationQueue } from './operations.ts'
import { registerModelRpc } from './rpc.ts'
import type { HostConnectionHandle } from './types.ts'

export { OperationQueue }
export { deployGlobalAgents, deployModes, dshHome, getStatus, installOne, repairMode, scanModes, scanPlugins, uninstallOne }
export { registerModelRpc }
export {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
}

export const name = 'dsh-redteam-model'
export const inject = ['connection']

/** Minimal structural face of the Cordis context this plugin needs. */
export interface HostContext {
  inject(services: readonly string[], callback: (services: Record<string, unknown>) => void): unknown
  effect(cleanup: () => void | (() => void), label?: string): unknown
}

export function apply(ctx: HostContext): void {
  registerConversationViewSettings(ctx)

  const queue = new OperationQueue(path.join(profileWebDir(), '.dsh-redteam-model-operations.json'))

  ctx.inject(['connection'], (web: Record<string, unknown>) => {
    const { connection } = web as { connection: HostConnectionHandle }
    registerModelRpc(connection, queue)
  })

  ctx.effect(() => () => {
    queue.dispose()
  }, 'dsh-redteam-model: queue')
}
