/** Plugin rows: install state, description, versions, and per-row actions. */
import { Button, IconCordisPluginOutline14, StateDot } from '@deepseek-ai/dsh-client-ui-primitives'
import type { PluginInstallState, PluginStatus, Translate } from './contracts.js'

function pluginDot(state: PluginInstallState): 'done' | 'warning' | 'error' {
  if (state === 'installed') return 'done'
  if (state === 'broken') return 'error'
  return 'warning'
}

function pluginLabelKey(state: PluginInstallState): 'pluginStateNotInstalled' | 'pluginStateInstalled' | 'pluginStateUpdateAvailable' | 'pluginStateBroken' {
  if (state === 'installed') return 'pluginStateInstalled'
  if (state === 'update-available') return 'pluginStateUpdateAvailable'
  if (state === 'broken') return 'pluginStateBroken'
  return 'pluginStateNotInstalled'
}

function versionLabel(plugin: PluginStatus, t: Translate): string {
  const installed = plugin.installedVersion ?? t('versionUnknown')
  const latest = plugin.latestVersion
  if (latest !== undefined && plugin.installState === 'update-available') {
    return `${installed} ${t('versionSeparator')} ${latest}`
  }
  return installed
}

export function PluginSection({
  plugins,
  t,
  busy,
  pending,
  onInstall,
  onUpdate,
  onRepair,
  onUninstall,
}: {
  plugins: PluginStatus[]
  t: Translate
  busy: boolean
  pending: boolean
  onInstall: (plugin: PluginStatus) => void
  onUpdate: (plugin: PluginStatus) => void
  onRepair: (plugin: PluginStatus) => void
  onUninstall: (plugin: PluginStatus) => void
}) {
  return (
    <section className="dsh-rtm-card">
      <div className="dsh-rtm-section-head">
        <h3 className="dsh-rtm-section-title">{t('pluginsTitle')}</h3>
      </div>
      {plugins.length === 0 ? (
        <p className="dsh-rtm-empty">{t('pluginsEmpty')}</p>
      ) : (
        <div className="dsh-rtm-plugins">
          {plugins.map(plugin => {
            const labelKey = pluginLabelKey(plugin.installState)
            const state = plugin.installState
            return (
              <div key={plugin.name} className="dsh-rtm-plugin-row">
                <IconCordisPluginOutline14 size={14} />
                <div className="dsh-rtm-plugin-main">
                  <div className="dsh-rtm-plugin-title-row">
                    <span className="dsh-rtm-plugin-name" title={plugin.name}>{plugin.title}</span>
                    <span className="dsh-rtm-plugin-plane">{plugin.mountPlane === 'preset' ? t('pluginPresetPlane') : t('pluginHostPlane')}</span>
                  </div>
                  <p className="dsh-rtm-plugin-desc">{plugin.description}</p>
                  <div className="dsh-rtm-plugin-meta">
                    <span className="dsh-rtm-plugin-state">
                      <StateDot state={pluginDot(state)} size={7} />
                      <span>{t(labelKey)}</span>
                    </span>
                    <span className="dsh-rtm-version">{versionLabel(plugin, t)}</span>
                  </div>
                </div>
                <div className="dsh-rtm-plugin-actions">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || pending || state !== 'not-installed'}
                    onClick={() => onInstall(plugin)}
                  >
                    {t('pluginInstall')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || pending || state !== 'update-available'}
                    onClick={() => onUpdate(plugin)}
                  >
                    {t('pluginUpdate')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || pending || state !== 'broken'}
                    onClick={() => onRepair(plugin)}
                  >
                    {t('pluginRepair')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="dsh-rtm-btn--danger"
                    disabled={busy || pending || state === 'not-installed'}
                    onClick={() => onUninstall(plugin)}
                  >
                    {t('pluginUninstall')}
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}
