/**
 * Minimal observable snapshot store with the `subscribe` + `getSnapshot`
 * shape React-friendly consumers expect. Hand-rolled so the client bundle
 * imports nothing from any @deepseek-ai package.
 */
export interface Store<T> {
  getSnapshot(): T
  subscribe(listener: () => void): () => void
}

export interface WritableStore<T> extends Store<T> {
  set(next: T): void
}

export function createStore<T>(initial: T): WritableStore<T> {
  let snapshot = initial
  const listeners = new Set<() => void>()
  return {
    getSnapshot: () => snapshot,
    subscribe: (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    set: (next) => {
      if (Object.is(snapshot, next)) return
      snapshot = next
      for (const listener of [...listeners]) {
        try {
          listener()
        } catch (error) {
          console.warn('[dsh-mcp-studio] listener failed', error)
        }
      }
    },
  }
}
