/** Web client plugin: registers the MCP Studio settings section bound to the plugin's loopback channel. */
import { createStudioPage } from './McpStudioPage.js'
import type { ClientContext } from './contracts.js'
import { StudioController } from './controller.js'
import { createStudioScope } from './studio-scope.js'
import { en, NS, zh } from './locales.js'
import { installStyles } from './styles.js'

export const name = 'dsh-mcp-studio-client'
export const inject = ['slots', 'locale', 'connection']

export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-mcp-studio: locale')
  ctx.effect(() => installStyles(), 'dsh-mcp-studio: styles')
  const scope = createStudioScope(ctx.connection)
  const controller = new StudioController(scope)
  const face = controller.inject()
  const t = ctx.locale.bind(NS)

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'mcp-studio',
    order: 110,
    label: () => t('nav'),
  }, createStudioPage(face, t, () => scope.status(), id => scope.diagnose(id), () => scope.clearExecutions())))
}
