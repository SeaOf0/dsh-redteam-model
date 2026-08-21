/** Client-side studio scope: settings read/write, live-status polling, diagnostics — all through the plugin's loopback channel. */
import type { DiagnoseReport, SettingsScope, StudioLive, StudioScopeSnapshot } from './contracts.js';
export declare class StudioScope implements SettingsScope {
    private readonly call;
    private snapshot;
    private readonly listeners;
    private tail;
    constructor(call: (endpoint: string, payload: unknown) => Promise<{
        ok: true;
        value: unknown;
    } | {
        ok: false;
        error: {
            message: string;
        };
    }>);
    getSnapshot: () => StudioScopeSnapshot;
    subscribe: (listener: () => void) => (() => void);
    set(field: string, value: unknown): Promise<void>;
    unset(field: string): Promise<void>;
    status(): Promise<StudioLive | {
        error: string;
    }>;
    clearExecutions(): Promise<{
        cleared: boolean;
    } | {
        error: string;
    }>;
    diagnose(id: string): Promise<DiagnoseReport | {
        error: string;
    }>;
    private load;
    private write;
    private publish;
}
export declare function createStudioScope(connection: {
    rpc: {
        call(channel: string, endpoint: string, payload: unknown): Promise<{
            ok: true;
            value: unknown;
        } | {
            ok: false;
            error: {
                message: string;
            };
        }>;
    };
}): SettingsScope;
