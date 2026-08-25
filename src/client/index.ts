/** Web client plugin: registers the Redteam Manager settings section. */
import { createAdminPage } from './AdminPage.js'
import type { ClientContext } from './contracts.js'
import { AdminController } from './controller.js'
import { en, NS, zh } from './locales.js'
import { installStyles } from './styles.js'

export const name = 'dsh-redteam-model-client'
export const inject = ['slots', 'locale', 'connection']

export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-redteam-model: locale')
  ctx.effect(() => installStyles(), 'dsh-redteam-model: styles')

  const controller = new AdminController(ctx.connection)
  const face = controller.inject()
  const t = ctx.locale.bind(NS)

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'redteam-manager',
    order: 120,
    label: () => t('nav'),
  }, createAdminPage(face, t)))
}
