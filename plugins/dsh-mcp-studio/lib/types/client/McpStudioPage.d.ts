/** The MCP Studio settings page: stats strip, server cards, JSON drawer, filter bar, execution log. */
import { type ReactElement } from 'react';
import type { DiagnoseReport, StudioLive, Translate } from './contracts.js';
import type { StudioCardFace } from './controller.js';
export declare function createStudioPage(face: StudioCardFace, t: Translate, pollStatus: () => Promise<StudioLive | {
    error: string;
}>, diagnose?: (id: string) => Promise<DiagnoseReport | {
    error: string;
}>, clearExecutions?: () => Promise<{
    cleared: boolean;
} | {
    error: string;
}>): () => ReactElement;
