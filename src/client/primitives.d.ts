/**
 * Ambient types for @deepseek-ai/dsh-client-ui-primitives.
 *
 * The host injects the primitives module at runtime, so the browser bundle
 * keeps it external. This declaration mirrors the published dev-time types
 * (packages/client/ui-primitives) for the subset used by this section.
 */
declare module '@deepseek-ai/dsh-client-ui-primitives' {
  import type { ButtonHTMLAttributes, ReactElement, ReactNode } from 'react'

  export type ButtonVariant = 'primary' | 'ghost' | 'outline' | 'toolbar'

  export function Button(props: {
    variant?: ButtonVariant
    size?: 'md' | 'sm'
    icon?: ReactNode
    className?: string | undefined
    children?: ReactNode
  } & ButtonHTMLAttributes<HTMLButtonElement>): ReactElement

  export function Modal(props: {
    open: boolean
    onClose: () => void
    title: string
    closeLabel?: string
    description?: string
    children?: ReactNode
    footer?: ReactNode
    className?: string
    contentClassName?: string
    headless?: boolean
  }): ReactElement | null

  export interface DisclosureRowProps {
    icon: ReactNode
    title: string
    open: boolean
    expandable: boolean
    onToggle: () => void
    expandOnRowClick?: boolean | undefined
    previewChevron?: boolean | undefined
    keepContentWhenOpen?: boolean | undefined
    collapsedContent?: ReactNode
    children?: ReactNode
    className?: string | undefined
    rowClassName?: string | undefined
    leadingClassName?: string | undefined
    chevronClassName?: string | undefined
    titleClassName?: string | undefined
  }

  export function DisclosureRow(props: DisclosureRowProps): ReactElement

  export type StateDotState = 'done' | 'warning' | 'ongoing' | 'error'

  export function StateDot(props: {
    state: StateDotState
    size?: number | undefined
    className?: string | undefined
  }): ReactElement

  export interface IconProps {
    size?: number
    className?: string
  }

  export function IconAgentPresetOutline16(props: IconProps): ReactElement
  export function IconCordisPluginOutline14(props: IconProps): ReactElement
  export function IconRefreshOutline16(props: IconProps): ReactElement
}
