/**
 * Loopback RPC surface for the Web page, all scoped to this plugin:
 * settings/get|mutate (namespace-scoped settings seam proxy), status
 * (live per-server state + tool catalog), diagnose, executions/clear.
 */
import type { ServerEntry, StudioSection } from './types.ts';
export declare const STUDIO_CHANNEL = "/dsh-mcp-studio";
export type RpcResult = {
    ok: true;
    value: unknown;
} | {
    ok: false;
    error: {
        code: string;
        message: string;
        details: Record<string, unknown>;
    };
};
export interface StudioSettingsDescriptor {
    readonly status: 'ready';
    readonly value: unknown;
    readonly base?: unknown;
    readonly user?: unknown;
    readonly revision: number;
    readonly writable: boolean;
    readonly mode: 'host';
    readonly applies?: unknown;
}
export interface HostSettingsService {
    readonly writable: boolean;
    describe(options?: {
        redactSecrets?: boolean;
    }): Array<{
        ns: string;
        value: unknown;
        base?: unknown;
        user?: unknown;
        revision: number;
        applies?: unknown;
    }>;
    mutate(ns: string, ops: Array<{
        op: 'set';
        path: string[];
        value: unknown;
    } | {
        op: 'unset';
        path: string[];
    }>, expectedRevision?: number): Promise<void>;
}
export interface HostConnectionHandle {
    rpc: {
        handle(channel: string, handler: (endpoint: string, payload: unknown) => Promise<RpcResult>, options: {
            authority: 'trusted-host' | 'loopback';
        }): unknown;
    };
}
export interface ExecutionRecord {
    readonly at: number;
    readonly server: string;
    readonly tool: string;
    readonly durationMs: number;
    readonly ok: boolean;
    readonly error?: string;
}
export interface ExecutionRing {
    readonly max: number;
    push(record: ExecutionRecord): void;
    recent(limit: number): readonly ExecutionRecord[];
    clear(): void;
}
export declare function createExecutionRing(max?: number): ExecutionRing;
export interface ToolView {
    readonly name: string;
    readonly description: string;
}
export type ServerState = 'disabled' | 'mounting' | 'connected' | 'unreachable' | 'error';
export interface ServerStatus {
    readonly id: string;
    readonly name: string;
    readonly transport: string;
    readonly state: ServerState;
    readonly error?: string;
    readonly toolCount: number;
    readonly tools: readonly ToolView[];
}
export interface StudioStatus {
    readonly servers: readonly ServerStatus[];
    readonly summary: {
        readonly total: number;
        readonly enabled: number;
        readonly connected: number;
        readonly tools: number;
    };
    readonly executions?: readonly ExecutionRecord[];
    readonly execCapacity?: number;
}
/** Mount lifecycle notes the mount engine records as fibers settle. */
export interface MountTracker {
    readonly states: Map<string, {
        state: 'mounting' | 'mounted' | 'error';
        error?: string;
    }>;
}
/** Build the status getter: per enabled server, aggregate its `mcp__<name>__*` tools out of the registry view. */
export declare function createStatusHandler(section: () => StudioSection, viewOf: () => unknown, tracker: MountTracker, executions?: ExecutionRing): () => Promise<RpcResult>;
export declare function registerStudioRpc(connection: HostConnectionHandle, settings: HostSettingsService, ns: string, status: () => Promise<RpcResult>, diagnose?: (id: string) => Promise<RpcResult>, clearExecutions?: () => void): void;
export type { ServerEntry };
