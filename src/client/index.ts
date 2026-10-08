/** Web client plugin: registers the Redteam Manager settings section. */
import { createAdminPage } from './AdminPage.js'
import type { ClientContext } from './contracts.js'
import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  decodeConversationViewSettings,
  type ConversationViewSettingsScope,
} from './conversationViewSettings.js'
import { AdminController } from './controller.js'
import { createSettingsScopeService } from './settingsScopeShim.js'
import { en, NS, zh } from './locales.js'
import { installStyles } from './styles.js'

export const name = 'dsh-redteam-model-client'
export const inject = ['slots', 'locale', 'connection']

export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-redteam-model: locale')
  ctx.effect(() => installStyles(), 'dsh-redteam-model: styles')

  // The dsh web client runtime ships no settingsScope service (dropped in the
  // 0.1.6 settings-UI refactor); five sibling client plugins and this one wait
  // on it forever. Capability probe instead of touching ctx.settingsScope —
  // reading an uninjected service on the real runtime throws, while the test
  // harness (a plain object carrying its own settingsScope) has no provide().
  const settingsScope = typeof ctx.provide === 'function'
    ? createSettingsScopeService()
    : (ctx as ClientContext).settingsScope
  if (typeof ctx.provide === 'function') {
    try {
      ctx.provide('settingsScope', settingsScope)
    } catch {
      // Another plugin provided it first; siblings bind to that instance and
      // ours keeps serving only this section page.
    }
  }

  const controller = new AdminController(ctx.connection)
  const face = controller.inject()
  const t = ctx.locale.bind(NS)
  const visibilityScope = settingsScope.bind({
    namespace: CONVERSATION_VIEW_SETTINGS_NAMESPACE,
    decode: decodeConversationViewSettings,
  }) as ConversationViewSettingsScope

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'redteam-manager',
    order: 120,
    label: () => t('nav'),
  }, createAdminPage(face, t, visibilityScope)))
}
