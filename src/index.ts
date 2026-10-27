/**
 * dsh-redteam-model management host plugin.
 *
 * The plugin itself never installs modes or sub-plugins at startup; all
 * mutations are triggered by the settings page through the loopback RPC.
 */

import path from 'node:path'

import { Service, type Context } from '@deepseek-ai/cordis'

import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
} from './conversationViewSettings.ts'
import { activeProfile, deployGlobalAgents, deployModes, dshHome, getStatus, healPresetPlanePlugins, installOne, profileWebDir, reconcileProfileBundles, repairMode, scanModes, scanPlugins, uninstallModes, uninstallOne } from './manager.ts'
import { detectEngineFlavor, isPackagedDesktopHost, normalizePresetComposition } from './manager.ts'
import { ENGINE_PACKAGES, NORMALIZER_VERSION, rewriteCompositionText } from './normalize.ts'
import { OperationQueue } from './operations.ts'
import { registerModelRpc } from './rpc.ts'
import type { HostConnectionHandle } from './types.ts'

export { OperationQueue }
export { activeProfile, deployGlobalAgents, deployModes, dshHome, getStatus, healPresetPlanePlugins, installOne, profileWebDir, reconcileProfileBundles, repairMode, scanModes, scanPlugins, uninstallModes, uninstallOne }
export { detectEngineFlavor, isPackagedDesktopHost, normalizePresetComposition }
export { ENGINE_PACKAGES, NORMALIZER_VERSION, rewriteCompositionText }
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

/**
 * dsh 0.2 no longer provides `webRuntime`, but six web plugins still inject it
 * for the trusted-host list. Expose the same shape from the current services.
 */
class WebRuntimeCompat extends Service {
  constructor(ctx: Context, private readonly hosts: () => string[]) {
    super(ctx, 'webRuntime')
  }

  get trustedHosts(): string[] {
    return this.hosts()
  }
}

/** Minimal structural face of the Cordis context this plugin needs. */
export interface HostContext {
  inject(services: readonly string[], callback: (services: Record<string, unknown>) => void): unknown
  effect(cleanup: () => void | (() => void), label?: string): unknown
  get?(name: string): unknown
}

export function apply(ctx: HostContext): void {
  registerConversationViewSettings(ctx)

  // dsh 0.2 dropped webRuntime; six web plugins still inject it for trustedHosts.
  ctx.inject(['connection', 'webServer'], (web: Record<string, unknown>) => {
    if (ctx.get?.('webRuntime') !== undefined) return
    const connection = web.connection as { trustedHosts?: unknown } | undefined
    const server = web.webServer as { host?: unknown } | undefined
    const hosts = (): string[] => {
      const configured = Array.isArray(connection?.trustedHosts)
        ? connection.trustedHosts.filter((entry): entry is string => typeof entry === 'string')
        : []
      const bind = typeof server?.host === 'string' ? server.host : undefined
      return bind === undefined || configured.includes(bind) ? configured : [...configured, bind]
    }
    new WebRuntimeCompat(ctx as unknown as Context, hosts)
  })

  // The plugin still never deploys modes or sub-plugins at startup, but the
  // profile rows of ALREADY installed plugins are its own bookkeeping: first
  // restore preset-plane dependencies a pre-fix profile detector stranded in
  // the wrong profile (their absence leaves preset rows that never start),
  // then heal a bundle manifest that an older release (or a bundle reconcile
  // reading a stale `dsh.bundle` declaration) left naming a preset-plane
  // plugin, which would otherwise report "broken — repair" on this boot and
  // every boot after it. Never fatal: an unreadable profile must not keep the
  // host from booting.
  try {
    healPresetPlanePlugins()
  } catch {
    /* getStatus reports the profile state to the settings page instead. */
  }
  try {
    reconcileProfileBundles()
  } catch {
    /* getStatus reports the profile state to the settings page instead. */
  }

  const queue = new OperationQueue(path.join(profileWebDir(), '.dsh-redteam-model-operations.json'))

  ctx.inject(['connection'], (web: Record<string, unknown>) => {
    const { connection } = web as { connection: HostConnectionHandle }
    registerModelRpc(connection, queue)
  })

  ctx.effect(() => () => {
    queue.dispose()
  }, 'dsh-redteam-model: queue')
}
