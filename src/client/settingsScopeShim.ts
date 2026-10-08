/**
 * Browser-local implementation of the settingsScope client service.
 *
 * The six collection client plugins (root manager + five conversation-view
 * owners) inject `settingsScope`; the dsh web client runtime shipped no such
 * service since the 0.1.6 settings-UI refactor, which left every one of them
 * pending forever. The root client provides this fallback first thing on
 * activation so the waiters resolve. Values persist in localStorage under the
 * bound namespace; snapshots report mode "memory" (no host settings channel is
 * involved) and decode failures fail open (value undefined).
 */

export interface SettingsScopeSnapshot<T> {
  status: 'loading' | 'ready' | 'unavailable'
  value: T | undefined
  writable: boolean
  mode: 'host' | 'memory'
}

export interface SettingsScopeBound<T> {
  getSnapshot(): SettingsScopeSnapshot<T>
  subscribe(listener: () => void): () => void
  set(field: string, value: unknown): Promise<void>
}

export interface SettingsScopeService {
  bind<T>(spec: { namespace: string; decode?: (section: unknown) => T | undefined }): SettingsScopeBound<T>
}

const STORAGE_PREFIX = 'dsh-redteam-model:settingsScope:'
const READY_SNAPSHOT_BASE = { status: 'ready', writable: true, mode: 'memory' } as const

function readSection(storage: Storage | undefined, namespace: string): Record<string, unknown> {
  if (!storage) return {}
  try {
    const raw = storage.getItem(STORAGE_PREFIX + namespace)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {}
    return parsed as Record<string, unknown>
  } catch {
    return {}
  }
}

function writeSection(storage: Storage | undefined, namespace: string, section: Record<string, unknown>): void {
  if (!storage) return
  try {
    storage.setItem(STORAGE_PREFIX + namespace, JSON.stringify(section))
  } catch {
    // Quota or privacy mode: keep serving the in-memory value for this page.
  }
}

export function createSettingsScopeService(): SettingsScopeService {
  let storage: Storage | undefined
  try {
    storage = window.localStorage
  } catch {
    storage = undefined
  }

  const listenersByNamespace = new Map<string, Set<() => void>>()

  const onStorage = (event: StorageEvent): void => {
    if (event.key === null || !event.key.startsWith(STORAGE_PREFIX)) return
    const namespace = event.key.slice(STORAGE_PREFIX.length)
    const listeners = listenersByNamespace.get(namespace)
    if (!listeners) return
    for (const listener of [...listeners]) listener()
  }
  // Cross-tab sync is best-effort: the offline test harness evaluates the
  // bundle against a minimal window stub without event APIs.
  if (typeof window.addEventListener === 'function') {
    window.addEventListener('storage', onStorage)
  }

  return {
    bind<T>(spec: { namespace: string; decode?: (section: unknown) => T | undefined }): SettingsScopeBound<T> {
      const { namespace, decode } = spec
      const listeners = new Set<() => void>()
      listenersByNamespace.set(namespace, listeners)
      return {
        getSnapshot(): SettingsScopeSnapshot<T> {
          const section = readSection(storage, namespace)
          const value = decode ? decode(section) : (section as T | undefined)
          return { ...READY_SNAPSHOT_BASE, value }
        },
        subscribe(listener: () => void): () => void {
          listeners.add(listener)
          return () => listeners.delete(listener)
        },
        async set(field: string, value: unknown): Promise<void> {
          const section = readSection(storage, namespace)
          section[field] = value
          writeSection(storage, namespace, section)
          for (const listener of [...listeners]) listener()
        },
      }
    },
  }
}
