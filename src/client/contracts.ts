/**
 * Client-side contract for the dsh-redteam-model management section.
 *
 * The channel and every RPC payload mirror the host plugin's settings RPC
 * surface. Keep this file in sync with the host `settings-rpc.ts` contract.
 */
import type { ReactElement } from 'react'
import type { LocaleKey } from './locales.js'

/** Loopback RPC channel exposed by the host-side dsh-redteam-model plugin. */
export const CHANNEL = '/dsh-redteam-model'

export type Translate = (key: LocaleKey, params?: Record<string, unknown>) => string

/** Shape of the host connection object handed to client plugins. */
export interface AdminConnectionHandle {
  rpc: {
    call(channel: string, endpoint: string, payload: unknown): Promise<HubRpcResult>
  }
}

export type HubRpcResult =
  | { ok: true; value: unknown }
  | { ok: false; error: { message: string } }

export interface AdminSummary {
  modesTotal: number
  modesReady: number
  pluginsTotal: number
  pluginsInstalled: number
  updatesAvailable: number
  busy: boolean
  profileError?: string
}

export type ModeLinkState = 'ok' | 'missing' | 'stale' | 'error'

export interface ModeStatus {
  id: string
  name: string
  summary: string
  linkState: ModeLinkState
  linkPath?: string
  ready: boolean
}

export type PluginInstallState = 'not-installed' | 'installed' | 'update-available' | 'broken'

export type PluginMountPlane = 'host' | 'preset'

export interface PluginStatus {
  name: string
  title: string
  description: string
  installState: PluginInstallState
  installedVersion?: string
  latestVersion?: string
  mountPlane: PluginMountPlane
}

export type OperationKind = 'deploy-modes' | 'install' | 'update' | 'uninstall' | 'repair'

export type OperationState = 'queued' | 'running' | 'done' | 'warned' | 'failed' | 'cancelled'

export interface OperationRecord {
  id: string
  kind: OperationKind
  target: string
  state: OperationState
  percent?: number | null
  detail?: string
  error?: string
}

export interface AdminStatus {
  summary: AdminSummary
  modes: ModeStatus[]
  plugins: PluginStatus[]
  operations: OperationRecord[]
}

export interface AdminOperationStart {
  kind: OperationKind
  target: string
  targets?: string[]
}

export interface AdminOperationStartResult {
  id: string
}

export interface AdminOperationCancelResult {
  cancelled: boolean
}

export interface AdminClearResult {
  cleared: boolean
}

export interface SettingsSectionComponent {
  (): ReactElement | null
}

export interface ClientContext {
  effect(factory: () => void | (() => void), label?: string): void
  connection: AdminConnectionHandle
  locale: {
    register(namespace: string, dictionaries: { readonly zh: Record<string, string>; readonly en: Record<string, string> }): () => void
    bind(namespace: string): Translate
  }
  slots: {
    inject(name: 'settings.section', register: () => unknown): void
    register(
      options: {
        readonly name: 'settings.section'
        readonly id: string
        readonly order: number
        readonly label: () => string
      },
      component: SettingsSectionComponent,
    ): () => void
  }
}
