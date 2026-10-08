/**
 * Icon-name compat across dsh hosts: pre-0.2 primitives name icons with a
 * pixel suffix (…Outline16 / …Outline14); 0.2 renamed the set to
 * Medium/Regular tiers. Resolve at module scope so either host resolves.
 */
import * as primitives from '@deepseek-ai/dsh-client-ui-primitives'

function pick<T>(legacyName: string, modernName: string): T {
  const table = primitives as unknown as Record<string, unknown>
  return (table[legacyName] ?? table[modernName]) as T
}

export type IconComponent = (props: { size?: number; className?: string }) => JSX.Element | null

export const IconRefresh = pick<IconComponent>('IconRefreshOutline16', 'IconRefreshOutlineRegular')
export const IconAgentPreset = pick<IconComponent>('IconAgentPresetOutline16', 'IconAgentPresetOutlineMedium')
export const IconCordisPlugin = pick<IconComponent>('IconCordisPluginOutline14', 'IconCordisPluginOutlineMedium')
