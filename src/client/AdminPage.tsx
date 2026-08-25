/** Redteam Manager settings section: status, batch actions, modes, plugins, operations. */
import { useCallback, useEffect, useState, type ReactElement } from 'react'
import { Button, IconRefreshOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import { type AdminOperationStart, type AdminStatus, type PluginStatus, type Translate } from './contracts.js'
import { errorMessage, type AdminFace } from './controller.js'
import { ConfirmDialog } from './ConfirmDialog.js'
import { ModeSection } from './ModeSection.js'
import { OperationsPanel } from './OperationsPanel.js'
import { PluginSection } from './PluginSection.js'
import { StatusSummary } from './StatusSummary.js'

const ACTIVE_POLL_MS = 2_000
const IDLE_POLL_MS = 10_000

function hasActiveOperations(status: AdminStatus | null): boolean {
  return status !== null && (status.summary.busy || status.operations.some(op => op.state === 'queued' || op.state === 'running'))
}

export function createAdminPage(face: AdminFace, t: Translate): () => ReactElement {
  return function AdminPage(): ReactElement {
    const [status, setStatus] = useState<AdminStatus | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [pending, setPending] = useState(false)
    const [uninstallTargets, setUninstallTargets] = useState<PluginStatus[] | null>(null)

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
      if (uninstallTargets === null) return
      const names = uninstallTargets.map(plugin => plugin.name)
      setPending(true)
      setError(null)
      try {
        await face.start({
          kind: 'uninstall',
          target: names.length === 1 ? names[0] ?? '' : 'installed',
          targets: names.length === 1 ? undefined : names,
        })
        setUninstallTargets(null)
        await refresh()
      } catch (cause) {
        setError(errorMessage(cause))
      } finally {
        setPending(false)
      }
    }, [face, refresh, uninstallTargets])

    const busy = hasActiveOperations(status)
    const runningCount = status?.operations.filter(op => op.state === 'queued' || op.state === 'running').length ?? 0

    const missingPlugins = status?.plugins.filter(plugin => plugin.installState === 'not-installed') ?? []
    const updatablePlugins = status?.plugins.filter(plugin => plugin.installState === 'update-available') ?? []
    const installedPlugins = status?.plugins.filter(plugin => plugin.installState !== 'not-installed') ?? []

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
    const confirmOpen = uninstallTargets !== null
    const confirmTargets = uninstallTargets?.map(plugin => plugin.name) ?? []

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

        <StatusSummary summary={status.summary} runningCount={runningCount} t={t} />

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
            onClick={() => setUninstallTargets(installedPlugins)}
          >
            {t('batchUninstallAll')} ({installedPlugins.length})
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

        <PluginSection
          plugins={status.plugins}
          t={t}
          busy={busy}
          pending={pending}
          onInstall={plugin => void runStart({ kind: 'install', target: plugin.name })}
          onUpdate={plugin => void runStart({ kind: 'update', target: plugin.name })}
          onRepair={plugin => void runStart({ kind: 'repair', target: plugin.name })}
          onUninstall={plugin => setUninstallTargets([plugin])}
        />

        <OperationsPanel
          operations={status.operations}
          t={t}
          busy={busy}
          pending={pending}
          onCancel={id => void runCancel(id)}
          onClear={() => void runClear()}
        />

        {confirmOpen && uninstallTargets !== null && (
          <ConfirmDialog
            open
            targets={confirmTargets}
            title={uninstallTargets.length > 1 ? t('confirmUninstallAllTitle') : t('confirmUninstallTitle')}
            description={t('confirmUninstallDesc')}
            confirmLabel={t('confirmConfirm')}
            cancelLabel={t('confirmCancel')}
            busy={pending}
            t={t}
            onClose={() => setUninstallTargets(null)}
            onConfirm={() => void confirmUninstall()}
          />
        )}
      </div>
    )
  }
}
