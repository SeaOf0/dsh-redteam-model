/**
 * Shared types for the dsh-redteam-model management host plugin.
 *
 * These are the wire contract for the loopback RPC channel. The web client
 * uses the same field names and state enumerations.
 */

export const RPC_CHANNEL = '/dsh-redteam-model'

export type OperationKind = 'deploy-modes' | 'remove-modes' | 'install' | 'update' | 'uninstall' | 'repair'
export type OperationState = 'queued' | 'running' | 'done' | 'warned' | 'failed' | 'cancelled'

export type ModeLinkState = 'ok' | 'missing' | 'stale' | 'error'
export type PluginInstallState = 'not-installed' | 'installed' | 'update-available' | 'broken'
export type MountPlane = 'host' | 'preset'

export interface AdminSummary {
  readonly modesTotal: number
  readonly modesReady: number
  readonly pluginsTotal: number
  readonly pluginsInstalled: number
  readonly updatesAvailable: number
  readonly busy: boolean
  readonly profileError?: string
}

export interface ModeStatus {
  readonly id: string
  readonly name: string
  readonly summary: string
  readonly linkState: ModeLinkState
  readonly linkPath?: string
  readonly ready: boolean
}

export interface PluginStatus {
  readonly name: string
  readonly title: string
  readonly description: string
  readonly installState: PluginInstallState
  readonly installedVersion?: string
  readonly latestVersion?: string
  readonly mountPlane: MountPlane
}

export interface OperationRecord {
  readonly id: string
  readonly kind: OperationKind
  readonly target: string
  readonly state: OperationState
  readonly percent?: number | null
  readonly detail?: string
  readonly error?: string
}

export interface AdminStatus {
  readonly summary: AdminSummary
  readonly modes: readonly ModeStatus[]
  readonly plugins: readonly PluginStatus[]
  readonly operations: readonly OperationRecord[]
}

export interface OperationStartPayload {
  readonly kind: OperationKind
  readonly target: string
  readonly targets?: readonly string[]
}

/**
 * RPC result shape. The failure branch matches the host client-connection
 * `rpcErrorSchema` contract (code/message/details) so the browser SDK can
 * validate the envelope and surface `message` instead of a zod union error.
 */
export type RpcResult =
  | { ok: true; value: unknown }
  | { ok: false; error: { code: 'internal'; message: string; details: Record<string, unknown> } }

/** Minimal face of the host `connection` service used by this plugin. */
export interface HostConnectionHandle {
  rpc: {
    handle(
      channel: string,
      handler: (endpoint: string, payload: unknown) => Promise<RpcResult>,
      options: { authority: 'trusted-host' | 'loopback' },
    ): unknown
  }
  /** Exact Fetch routes under /api (Host 0.1.2+); absent on legacy Hosts. */
  fetch?: {
    register(route: {
      path: string
      methods: string[]
      requestBody: 'buffered' | 'streamed'
      fetch: (request: Request) => Promise<Response>
    }): unknown
  }
}
