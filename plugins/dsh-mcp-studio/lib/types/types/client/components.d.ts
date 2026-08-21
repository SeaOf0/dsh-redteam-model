/** Shared UI building blocks: fields, pair editor, toggle, store hook. */
import { type ReactElement, type ReactNode } from 'react';
import type { Translate } from './contracts.js';
import type { WritableStore } from './store.js';
/** Subscribe a component to one controller store snapshot. */
export declare function useStoreState<T>(store: WritableStore<T>): T;
export declare function Field(props: {
    label: string;
    hint?: string;
    children: ReactNode;
}): ReactElement;
export declare function PairEditor(props: {
    pairs: Array<{
        key: string;
        value: string;
    }>;
    t: Translate;
    onChange(pairs: Array<{
        key: string;
        value: string;
    }>): void;
}): ReactElement;
export declare function ToggleSwitch(props: {
    checked: boolean;
    label: string;
    onChange(checked: boolean): void;
}): ReactElement;
