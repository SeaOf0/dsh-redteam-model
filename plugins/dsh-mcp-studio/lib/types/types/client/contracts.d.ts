/** Client-side contract types; the section shape mirrors the Host schema (src/types.ts). */
import type { ReactElement } from 'react';
import type { StudioLocaleKey } from './locales.js';
import type { StudioCardState } from './controller.js';
export type Translate = (key: StudioLocaleKey, params?: Record<string, unknown>) => string;
export type Transport = 'stdio' | 'streamable-http';
export interface Pair {
    key: string;
    value: string;
}
export interface ServerDraft {
    id: string;
    enabled: boolean;
    name: string;
    transport: Transport;
    command: string;
    argsLine: string;
    env: Pair[];
    cwd: string;
    url: string;
    headers: Pair[];
    toolCallTimeoutMs: number;
    failOnStartupError: boolean;
}
export interface StudioDraft {
    servers: ServerDraft[];
}
export type DraftError = string;
export interface StudioScopeSnapshot {
    status: 'loading' | 'ready' | 'unavailable';
    value: unknown;
    base: unknown;
    user: unknown;
    revision: number | undefined;
    writable: boolean;
    mode: 'host';
}
export type ServerLiveState = 'disabled' | 'mounting' | 'connected' | 'unreachable' | 'error';
export interface ServerLive {
    readonly id: string;
    readonly name: string;
    readonly transport: string;
    readonly state: ServerLiveState;
    readonly error?: string;
    readonly toolCount: number;
    readonly tools: ReadonlyArray<{
        name: string;
        description: string;
    }>;
}
export interface ExecutionRecord {
    readonly at: number;
    readonly server: string;
    readonly tool: string;
    readonly durationMs: number;
    readonly ok: boolean;
    readonly error?: string;
}
export interface DiagnoseReport {
    readonly ok: boolean;
    readonly elapsedMs: number;
    readonly protocolVersion?: string;
    readonly serverName?: string;
    readonly serverVersion?: string;
    readonly toolCount?: number;
    readonly error?: string;
}
export interface StudioLive {
    readonly servers: readonly ServerLive[];
    readonly summary: {
        readonly total: number;
        readonly enabled: number;
        readonly connected: number;
        readonly tools: number;
    };
    readonly executions?: readonly ExecutionRecord[];
    readonly execCapacity?: number;
}
export type HubRpcResult = {
    ok: true;
    value: unknown;
} | {
    ok: false;
    error: {
        message: string;
    };
};
export interface StudioConnectionHandle {
    rpc: {
        call(channel: string, endpoint: string, payload: unknown): Promise<HubRpcResult>;
    };
}
export interface SettingsScope {
    getSnapshot(): StudioScopeSnapshot;
    subscribe(listener: () => void): () => void;
    set(field: string, value: unknown): Promise<void>;
    unset(field: string): Promise<void>;
    status(): Promise<StudioLive | {
        error: string;
    }>;
    diagnose(id: string): Promise<DiagnoseReport | {
        error: string;
    }>;
    clearExecutions(): Promise<{
        cleared: boolean;
    } | {
        error: string;
    }>;
}
export interface SettingsSectionComponent {
    (): ReactElement | null;
}
export interface ClientContext {
    effect(factory: () => void | (() => void), label?: string): void;
    connection: StudioConnectionHandle;
    locale: {
        register(namespace: string, dictionaries: {
            readonly zh: Record<string, string>;
            readonly en: Record<string, string>;
        }): () => void;
        bind(namespace: string): Translate;
    };
    slots: {
        inject(name: 'settings.section', register: () => unknown): void;
        register(options: {
            readonly name: 'settings.section';
            readonly id: string;
            readonly order: number;
            readonly label: () => string;
        }, component: SettingsSectionComponent): () => void;
    };
}
export interface StudioCardStateLike extends StudioCardState {
}
