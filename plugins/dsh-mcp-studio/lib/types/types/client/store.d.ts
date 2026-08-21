/**
 * Minimal observable snapshot store with the `subscribe` + `getSnapshot`
 * shape React-friendly consumers expect. Hand-rolled so the client bundle
 * imports nothing from any @deepseek-ai package.
 */
export interface Store<T> {
    getSnapshot(): T;
    subscribe(listener: () => void): () => void;
}
export interface WritableStore<T> extends Store<T> {
    set(next: T): void;
}
export declare function createStore<T>(initial: T): WritableStore<T>;
