/** One server card: status dot, name, transport chip, summary, tool-count badge (opens a preview popover), switch, and delete. Config expands only on manual click. */
import { type ReactElement } from 'react';
import type { DiagnoseReport, ServerDraft, ServerLive, Translate } from './contracts.js';
export declare function ServerCard(props: {
    server: ServerDraft;
    live: ServerLive | undefined;
    open: boolean;
    onToggle(): void;
    t: Translate;
    disabled: boolean;
    onUpdate(next: ServerDraft): void;
    onRemove(): void;
    diagnose?(id: string): Promise<DiagnoseReport | {
        error: string;
    }>;
}): ReactElement;
