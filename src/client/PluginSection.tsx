/** Plugin rows: install state, description, versions, and per-row actions. */
import { Button, IconCordisPluginOutline14, StateDot } from '@deepseek-ai/dsh-client-ui-primitives'
import type { PluginInstallState, PluginStatus, Translate } from './contracts.js'
import {
  VIEW_FIELD_BY_PLUGIN,
  type ConversationViewField,
  type ConversationViewSettings,
} from './conversationViewSettings.js'

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

function isEnabledInProfile(plugin: PluginStatus): boolean {
  return plugin.installState !== 'not-installed'
}

export function PluginSection({
  plugins,
  t,
  busy,
  pending,
  visibility,
  visibilityWritable,
  visibilityPending,
  onSetEnabled,
  onSetViewVisible,
  onUpdate,
  onRepair,
}: {
  plugins: PluginStatus[]
  t: Translate
  busy: boolean
  pending: boolean
  visibility: ConversationViewSettings
  visibilityWritable: boolean
  visibilityPending: ConversationViewField | null
  onSetEnabled: (plugin: PluginStatus, enabled: boolean) => void
  onSetViewVisible: (field: ConversationViewField, visible: boolean) => void
  onUpdate: (plugin: PluginStatus) => void
  onRepair: (plugin: PluginStatus) => void
}) {
  return (
    <section className="dsh-rtm-card">
      <div className="dsh-rtm-section-head">
        <h3 className="dsh-rtm-section-title">{t('pluginsTitle')}</h3>
      </div>
      <div className="dsh-rtm-view-settings-summary">
        <p className="dsh-rtm-view-settings-note">{t('pluginViewSettingsScope')}</p>
        {!visibilityWritable && (
          <p className="dsh-rtm-view-settings-unavailable" role="status">{t('pluginViewSettingsUnavailable')}</p>
        )}
      </div>
      {plugins.length === 0 ? (
        <p className="dsh-rtm-empty">{t('pluginsEmpty')}</p>
      ) : (
        <div className="dsh-rtm-plugins">
          {plugins.map(plugin => {
            const labelKey = pluginLabelKey(plugin.installState)
            const state = plugin.installState
            const viewField = VIEW_FIELD_BY_PLUGIN[plugin.name as keyof typeof VIEW_FIELD_BY_PLUGIN]
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
                  <div className="dsh-rtm-plugin-switches">
                    <label className="dsh-rtm-switch-row" title={t('pluginEnabledRestartHint')}>
                      <span className="dsh-rtm-switch-copy">
                        <span>{t('pluginEnabledInProfile')}</span>
                        <small>{t('pluginEnabledRestartHint')}</small>
                      </span>
                      <span className="dsh-rtm-switch">
                        <input
                          type="checkbox"
                          role="switch"
                          checked={isEnabledInProfile(plugin)}
                          disabled={busy || pending}
                          aria-label={`${plugin.title}: ${t('pluginEnabledInProfile')}`}
                          onChange={event => onSetEnabled(plugin, event.target.checked)}
                        />
                        <i aria-hidden="true" />
                      </span>
                    </label>
                    {viewField !== undefined && (
                      <label className="dsh-rtm-switch-row" title={t('pluginViewScopeHint')}>
                        <span className="dsh-rtm-switch-copy">
                          <span>{t('pluginShowConversationView')}</span>
                          <small>{t('pluginViewLiveHint')}</small>
                        </span>
                        <span className="dsh-rtm-switch">
                          <input
                            type="checkbox"
                            role="switch"
                            checked={visibility[viewField]}
                            disabled={!visibilityWritable || visibilityPending !== null}
                            aria-label={`${plugin.title}: ${t('pluginShowConversationView')}`}
                            onChange={event => onSetViewVisible(viewField, event.target.checked)}
                          />
                          <i aria-hidden="true" />
                        </span>
                      </label>
                    )}
                  </div>
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
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}
