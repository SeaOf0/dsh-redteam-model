/** Persistent Host settings for repository-owned conversation views. */
import { settingsNamespace, type SettingsNamespace } from '@deepseek-ai/dsh-settings'
import z from '@deepseek-ai/schemastery'
import {
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  type ConversationViewSettings,
} from './conversationViewState.ts'

export {
  conversationViewWriteApplied,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
} from './conversationViewState.ts'
export type { ConversationViewField, ConversationViewSettings } from './conversationViewState.ts'

export const CONVERSATION_VIEW_SETTINGS_NAMESPACE = settingsNamespace('redteam-manager-ui')

export const ConversationViewSettingsSchema: z<ConversationViewSettings> = z.object({
  showCampaignMemory: z.boolean().default(true),
  showAttackAtlas: z.boolean().default(true),
  showRedteamResults: z.boolean().default(true),
  showHunter: z.boolean().default(true),
  showWebshellManager: z.boolean().default(true),
})

interface HostSettingsService {
  register<T>(
    namespace: SettingsNamespace,
    schema: z<T>,
    options?: { applies?: 'live' | 'restart' },
  ): unknown
}

export interface ConversationViewSettingsContext {
  inject(services: readonly string[], callback: (services: Record<string, unknown>) => void): unknown
}

/** Register lazily so older Hosts without the settings service still boot. */
export function registerConversationViewSettings(ctx: ConversationViewSettingsContext): void {
  ctx.inject(['settings'], (services: Record<string, unknown>) => {
    const { settings } = services as { settings: HostSettingsService }
    settings.register(CONVERSATION_VIEW_SETTINGS_NAMESPACE, ConversationViewSettingsSchema, { applies: 'live' })
  })
}
