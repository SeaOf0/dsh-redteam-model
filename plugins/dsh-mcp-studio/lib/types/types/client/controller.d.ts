/** Staged form controller: edits stage a replacement section; Save writes it through the scope. */
import type { DraftError, ServerDraft, SettingsScope, StudioDraft } from './contracts.js';
import { type WritableStore } from './store.js';
export interface StudioCardState {
    status: 'loading' | 'ready' | 'unavailable';
    writable: boolean;
    view: StudioDraft;
    dirty: boolean;
    saving: boolean;
    failed: boolean;
    errors: DraftError[];
}
export interface StudioCardActions {
    addServer(): string;
    updateServerDraft(next: ServerDraft): void;
    removeServer(id: string): void;
    importMcpJson(text: string): {
        servers: number;
        warnings: string[];
    } | {
        error: string;
    };
    moveServer(id: string, targetId: string): void;
    save(): Promise<void>;
    discard(): void;
}
export interface StudioCardFace extends StudioCardActions {
    hooks: {
        studio: WritableStore<StudioCardState>;
    };
}
export declare function sectionToDraft(section: unknown): StudioDraft;
/** Client mirror of the Host cross-field validator. */
export declare function validateDraft(section: StudioDraft): DraftError[];
export declare class StudioController {
    private readonly scope;
    private readonly store;
    private staged;
    private saving;
    private failed;
    constructor(scope: SettingsScope);
    getStore(): WritableStore<StudioCardState>;
    private currentDraft;
    private projection;
    private publish;
    /** Adds a blank row and returns its id (the page expands only these). */
    addServer(): string;
    updateServerDraft(next: ServerDraft): void;
    removeServer(id: string): void;
    /** Parse pasted MCP-client JSON and stage every server entry as a new row. */
    importMcpJson(text: string): {
        servers: number;
        warnings: string[];
    } | {
        error: string;
    };
    /** Reorder: move `id` directly before `targetId` in the staged draft. */
    moveServer(id: string, targetId: string): void;
    save(): Promise<void>;
    discard(): void;
    inject(): StudioCardFace;
}
