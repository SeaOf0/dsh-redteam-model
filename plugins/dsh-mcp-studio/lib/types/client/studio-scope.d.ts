/** Client-side studio scope: settings read/write, live-status polling, diagnostics — all through the plugin's loopback channel. */
import type { DiagnoseReport, SettingsScope, StudioConnectionHandle, StudioLive, StudioScopeSnapshot } from './contracts.js';
export declare class StudioScope implements SettingsScope {
    private readonly connection;
    private snapshot;
    private readonly listeners;
    private tail;
    private channel;
    private rpcId;
    /** Resolves once the first settings read settled (ready or unavailable). */
    readonly ready: Promise<void>;
    constructor(connection: StudioConnectionHandle);
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
    /**
     * Modern Hosts (0.1.2+) expose exact Fetch routes under /api, which cannot
     * travel through connection.rpc.call. Legacy Hosts only serve the bare
     * channel, so probe /api first and stick with whichever transport answered.
     */
    private call;
    private invokeApi;
    private write;
    private publish;
}
export declare function createStudioScope(connection: StudioConnectionHandle): SettingsScope;
