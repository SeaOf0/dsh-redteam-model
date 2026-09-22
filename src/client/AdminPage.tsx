/** Redteam Manager settings section: overview, modes, plugins, and logs. */
import { useCallback, useEffect, useState, type ReactElement } from 'react'
import { Button, IconRefreshOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import { type AdminOperationStart, type AdminStatus, type PluginStatus, type Translate } from './contracts.js'
import {
  conversationViewWriteApplied,
  effectiveConversationViewSettings,
  type ConversationViewField,
  type ConversationViewSettingsScope,
} from './conversationViewSettings.js'
import { errorMessage, type AdminFace } from './controller.js'
import { ConfirmDialog } from './ConfirmDialog.js'
import { ModeSection } from './ModeSection.js'
import { OperationsPanel } from './OperationsPanel.js'
import { OverviewPanel, type ManagerPage } from './OverviewPanel.js'
import { PluginSection } from './PluginSection.js'

const ACTIVE_POLL_MS = 2_000
const IDLE_POLL_MS = 10_000

const MANAGER_PAGES = [
  { id: 'overview', label: 'pageOverview' },
  { id: 'modes', label: 'pageModes' },
  { id: 'plugins', label: 'pagePlugins' },
  { id: 'logs', label: 'pageLogs' },
] as const satisfies ReadonlyArray<{ id: ManagerPage; label: 'pageOverview' | 'pageModes' | 'pagePlugins' | 'pageLogs' }>

function hasActiveOperations(status: AdminStatus | null): boolean {
  return status !== null && (status.summary.busy || status.operations.some(op => op.state === 'queued' || op.state === 'running'))
}

/** One pending destructive confirmation: plugin removal or mode removal. */
type UninstallRequest =
  | { readonly kind: 'uninstall'; readonly names: readonly string[] }
  | { readonly kind: 'remove-modes'; readonly names: readonly string[] }

export function createAdminPage(face: AdminFace, t: Translate, visibilityScope: ConversationViewSettingsScope): () => ReactElement {
  return function AdminPage(): ReactElement {
    const [activePage, setActivePage] = useState<ManagerPage>('overview')
    const [status, setStatus] = useState<AdminStatus | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [pending, setPending] = useState(false)
    const [uninstallRequest, setUninstallRequest] = useState<UninstallRequest | null>(null)
    const [visibilitySnapshot, setVisibilitySnapshot] = useState(() => visibilityScope.getSnapshot())
    const [visibilityPending, setVisibilityPending] = useState<ConversationViewField | null>(null)

    const refresh = useCallback(async () => {
      try {
        const next = await face.status()
        setStatus(next)
        setError(null)
      } catch (cause) {
        setError(errorMessage(cause))
      }
    }, [face])

    // Poll while mounted: fast while anything is queued/running, slow otherwise.
    useEffect(() => {
      let alive = true
      let timer: number | undefined

      const tick = async () => {
        try {
          const next = await face.status()
          if (!alive) return
          setStatus(next)
          setError(null)
          timer = window.setTimeout(() => void tick(), hasActiveOperations(next) ? ACTIVE_POLL_MS : IDLE_POLL_MS)
        } catch (cause) {
          if (!alive) return
          setError(errorMessage(cause))
          timer = window.setTimeout(() => void tick(), IDLE_POLL_MS)
        }
      }

      void tick()
      return () => {
        alive = false
        if (timer !== undefined) window.clearTimeout(timer)
      }
    }, [face])

    // The settings mirror is independent of the status poll and is bound once in apply().
    useEffect(() => {
      const publish = () => setVisibilitySnapshot(visibilityScope.getSnapshot())
      const unsubscribe = visibilityScope.subscribe(publish)
      publish()
      return unsubscribe
    }, [visibilityScope])

    const visibility = effectiveConversationViewSettings(visibilitySnapshot)
    const visibilityWritable = visibilitySnapshot.status === 'ready'
      && visibilitySnapshot.mode === 'host'
      && visibilitySnapshot.writable

    const setViewVisible = useCallback(async (field: ConversationViewField, visible: boolean) => {
      if (!visibilityWritable) return
      setVisibilityPending(field)
      setError(null)
      try {
        await visibilityScope.set(field, visible)
        const settled = visibilityScope.getSnapshot()
        setVisibilitySnapshot(settled)
        if (!conversationViewWriteApplied(settled, field, visible)) {
          throw new Error(t('pluginViewSettingsSaveFailed'))
        }
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setVisibilityPending(null)
      }
    }, [t, visibilityScope, visibilityWritable])

    const runStart = useCallback(async (request: AdminOperationStart) => {
      setPending(true)
      setError(null)
      try {
        await face.start(request)
        await refresh()
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setPending(false)
      }
    }, [face, refresh])

    const runCancel = useCallback(async (id: string) => {
      setPending(true)
      setError(null)
      try {
        await face.cancel(id)
        await refresh()
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setPending(false)
      }
    }, [face, refresh])

    const runClear = useCallback(async () => {
      setPending(true)
      setError(null)
      try {
        await face.clear()
        await refresh()
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setPending(false)
      }
    }, [face, refresh])

    const confirmUninstall = useCallback(async () => {
      if (uninstallRequest === null) return
      setPending(true)
      setError(null)
      try {
        if (uninstallRequest.kind === 'remove-modes') {
          // One link covers every mode, so the whole plane is one operation;
          // the handler decides what it may remove from what it owns.
          await face.start({ kind: 'remove-modes', target: 'modes' })
        } else {
          const names = uninstallRequest.names
          await face.start({
            kind: 'uninstall',
            target: names.length === 1 ? names[0] ?? '' : 'installed',
            targets: names.length === 1 ? undefined : [...names],
          })
        }
        setUninstallRequest(null)
        await refresh()
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setPending(false)
      }
    }, [face, refresh, uninstallRequest])

    const busy = hasActiveOperations(status)
    const runningCount = status?.operations.filter(op => op.state === 'queued' || op.state === 'running').length ?? 0

    const missingPlugins = status?.plugins.filter(plugin => plugin.installState === 'not-installed') ?? []
    const updatablePlugins = status?.plugins.filter(plugin => plugin.installState === 'update-available') ?? []
    const installedPlugins = status?.plugins.filter(plugin => plugin.installState !== 'not-installed') ?? []
    // Deployed means a live link or a copy the manager still owns ('stale');
    // a foreign or absent entry is neither removable nor deployable as ours.
    const deployed = status?.modes.filter(mode => mode.linkState === 'ok' || mode.linkState === 'stale') ?? []
    const notReady = status?.modes.filter(mode => mode.linkState !== 'ok') ?? []

    if (status === null) {
      return (
        <div className="dsh-rtm">
          {error !== null && (
            <div className="dsh-rtm-error" role="alert">
              <span className="dsh-rtm-error-title">{t('errorBannerTitle')}</span>
              <span className="dsh-rtm-error-message">{error}</span>
            </div>
          )}
          <div className="dsh-rtm-loading">
            <span className="dsh-rtm-spin" aria-label={t('loading')} />
            {t('loading')}
          </div>
        </div>
      )
    }

    const batchDisabled = busy || pending
    const confirmOpen = uninstallRequest !== null
    const confirmTargets = uninstallRequest === null ? [] : [...uninstallRequest.names]
    const confirmModes = uninstallRequest?.kind === 'remove-modes'
    const confirmTitle = confirmModes
      ? t('confirmUninstallModesTitle')
      : confirmTargets.length > 1 ? t('confirmUninstallAllTitle') : t('confirmUninstallTitle')
    const confirmDescription = confirmModes ? t('confirmUninstallModesDesc') : t('confirmUninstallDesc')
    const activePageButtonId = `dsh-rtm-page-${activePage}`

    return (
      <div className="dsh-rtm">
        <div className="dsh-rtm-head">
          <div>
            <h2 className="dsh-rtm-title">{t('title')}</h2>
            <p className="dsh-rtm-sub">{t('subtitle')}</p>
          </div>
          <div className="dsh-rtm-toolbar">
            {busy && <span className="dsh-rtm-muted">{t('busyHint')}</span>}
            <Button
              size="sm"
              variant="outline"
              icon={<IconRefreshOutline16 size={14} />}
              disabled={pending}
              onClick={() => void refresh()}
            >
              {t('refresh')}
            </Button>
          </div>
        </div>

        {error !== null && (
          <div className="dsh-rtm-error" role="alert">
            <span className="dsh-rtm-error-title">{t('requestFailed')}</span>
            <span className="dsh-rtm-error-message">{error}</span>
          </div>
        )}

        {status.summary.profileError !== undefined && status.summary.profileError !== '' && (
          <div className="dsh-rtm-error" role="alert">
            <span className="dsh-rtm-error-title">{t('profileError')}</span>
            <span className="dsh-rtm-error-message">{status.summary.profileError}</span>
          </div>
        )}

        <p className="dsh-rtm-restart-hint">{t('restartHint')}</p>

        <nav className="dsh-rtm-page-nav" aria-label={t('managerPages')}>
          {MANAGER_PAGES.map(page => (
            <button
              key={page.id}
              id={`dsh-rtm-page-${page.id}`}
              type="button"
              className={activePage === page.id ? 'dsh-rtm-page-button is-active' : 'dsh-rtm-page-button'}
              aria-current={activePage === page.id ? 'page' : undefined}
              aria-controls="dsh-rtm-page-content"
              onClick={() => setActivePage(page.id)}
            >
              {t(page.label)}
            </button>
          ))}
        </nav>

        <div id="dsh-rtm-page-content" className="dsh-rtm-page-content" role="region" aria-labelledby={activePageButtonId}>
          {activePage === 'overview' && (
            <OverviewPanel status={status} runningCount={runningCount} t={t} onNavigate={setActivePage} />
          )}

          {activePage === 'modes' && (
            <>
              <div className="dsh-rtm-batchbar">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={batchDisabled || notReady.length === 0}
                  onClick={() => void runStart({ kind: 'deploy-modes', target: 'modes' })}
                >
                  {t('batchDeployModesAll')} ({notReady.length})
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="dsh-rtm-btn--danger"
                  disabled={batchDisabled || deployed.length === 0}
                  onClick={() => setUninstallRequest({ kind: 'remove-modes', names: deployed.map(mode => mode.id) })}
                >
                  {t('batchUninstallModesAll')} ({deployed.length})
                </Button>
                {busy && <span className="dsh-rtm-batchbar-hint">{t('busyHint')}</span>}
              </div>

              <ModeSection
                modes={status.modes}
                t={t}
                busy={busy}
                pending={pending}
                onDeploy={mode => void runStart({ kind: 'deploy-modes', target: mode.id })}
                onRepair={mode => void runStart({ kind: 'repair', target: mode.id })}
              />
            </>
          )}

          {activePage === 'plugins' && (
            <>
              <div className="dsh-rtm-batchbar">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={batchDisabled || missingPlugins.length === 0}
                  onClick={() => void runStart({
                    kind: 'install',
                    target: 'missing',
                    targets: missingPlugins.map(plugin => plugin.name),
                  })}
                >
                  {t('batchInstallMissing')} ({missingPlugins.length})
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={batchDisabled || updatablePlugins.length === 0}
                  onClick={() => void runStart({
                    kind: 'update',
                    target: 'updates',
                    targets: updatablePlugins.map(plugin => plugin.name),
                  })}
                >
                  {t('batchUpdateAll')} ({updatablePlugins.length})
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="dsh-rtm-btn--danger"
                  disabled={batchDisabled || installedPlugins.length === 0}
                  onClick={() => setUninstallRequest({ kind: 'uninstall', names: installedPlugins.map(plugin => plugin.name) })}
                >
                  {t('batchUninstallAll')} ({installedPlugins.length})
                </Button>
                {busy && <span className="dsh-rtm-batchbar-hint">{t('busyHint')}</span>}
              </div>

              <PluginSection
                plugins={status.plugins}
                t={t}
                busy={busy}
                pending={pending}
                visibility={visibility}
                visibilityWritable={visibilityWritable}
                visibilityPending={visibilityPending}
                onSetEnabled={(plugin, enabled) => {
                  if (enabled) {
                    void runStart({ kind: 'install', target: plugin.name })
                    return
                  }
                  setUninstallRequest({ kind: 'uninstall', names: [plugin.name] })
                }}
                onSetViewVisible={(field, visible) => void setViewVisible(field, visible)}
                onUpdate={plugin => void runStart({ kind: 'update', target: plugin.name })}
                onRepair={plugin => void runStart({ kind: 'repair', target: plugin.name })}
              />
            </>
          )}

          {activePage === 'logs' && (
            <OperationsPanel
              operations={status.operations}
              t={t}
              busy={busy}
              pending={pending}
              onCancel={id => void runCancel(id)}
              onClear={() => void runClear()}
            />
          )}
        </div>

        {confirmOpen && uninstallRequest !== null && (
          <ConfirmDialog
            open
            targets={confirmTargets}
            title={confirmTitle}
            description={confirmDescription}
            confirmLabel={t('confirmConfirm')}
            cancelLabel={t('confirmCancel')}
            busy={pending}
            t={t}
            onClose={() => setUninstallRequest(null)}
            onConfirm={() => void confirmUninstall()}
          />
        )}
      </div>
    )
  }
}
