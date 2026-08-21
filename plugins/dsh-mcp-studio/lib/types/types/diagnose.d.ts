import type { ServerEntry } from './types.ts';
export interface DiagnoseReport {
    readonly ok: boolean;
    readonly elapsedMs: number;
    readonly protocolVersion?: string;
    readonly serverName?: string;
    readonly serverVersion?: string;
    readonly toolCount?: number;
    readonly error?: string;
}
/** Run one full handshake: a throwaway stdio child, or initialize + tools/list over HTTP. */
export declare function diagnoseServer(server: ServerEntry): Promise<DiagnoseReport>;
