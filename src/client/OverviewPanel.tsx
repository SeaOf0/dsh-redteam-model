/** Read-only status monitor derived from the Manager's existing status payload. */
import { Button, StateDot } from '@deepseek-ai/dsh-client-ui-primitives'
import type { AdminStatus, Translate } from './contracts.js'
import { StatusSummary } from './StatusSummary.js'

export type ManagerPage = 'overview' | 'modes' | 'plugins' | 'logs'

type DetailPage = Exclude<ManagerPage, 'overview'>

export function OverviewPanel({
  status,
  runningCount,
  t,
  onNavigate,
}: {
  status: AdminStatus
  runningCount: number
  t: Translate
  onNavigate: (page: DetailPage) => void
}) {
  const modeAttention = status.modes.filter(mode => !mode.ready).length
  const pluginAttention = status.plugins.filter(plugin => plugin.installState !== 'installed').length
  const operationWarnings = status.operations.filter(operation => operation.state === 'failed' || operation.state === 'warned').length
  const profileError = status.summary.profileError !== undefined && status.summary.profileError !== ''
  const overall = profileError
    ? 'error'
    : runningCount > 0
      ? 'busy'
      : modeAttention > 0 || pluginAttention > 0
        ? 'attention'
        : 'healthy'

  const overallLabel = overall === 'error'
    ? t('overallError')
    : overall === 'busy'
      ? t('overallBusy')
      : overall === 'attention'
        ? t('overallAttention')
        : t('overallHealthy')

  return (
    <div className="dsh-rtm-overview">
      <StatusSummary summary={status.summary} runningCount={runningCount} t={t} />

      <section className={`dsh-rtm-overall dsh-rtm-overall--${overall}`} aria-live="polite">
        <StateDot
          state={overall === 'healthy' ? 'done' : overall === 'busy' ? 'ongoing' : overall === 'error' ? 'error' : 'warning'}
          size={8}
        />
        <span>{t('overallLabel')}</span>
        <strong>{overallLabel}</strong>
      </section>

      <section className="dsh-rtm-card">
        <div className="dsh-rtm-section-head">
          <h3 className="dsh-rtm-section-title">{t('attentionTitle')}</h3>
        </div>
        <div className="dsh-rtm-attention-list">
          <AttentionRow
            label={t('overviewModesLabel')}
            value={modeAttention}
            detail={modeAttention === 0 ? t('overviewModesHealthy') : t('overviewModesAttention')}
            attention={modeAttention > 0}
            actionLabel={t('viewDetails')}
            onClick={() => onNavigate('modes')}
          />
          <AttentionRow
            label={t('overviewPluginsLabel')}
            value={pluginAttention}
            detail={pluginAttention === 0 ? t('overviewPluginsHealthy') : t('overviewPluginsAttention')}
            attention={pluginAttention > 0}
            actionLabel={t('viewDetails')}
            onClick={() => onNavigate('plugins')}
          />
          <AttentionRow
            label={t('overviewOperationsLabel')}
            value={operationWarnings}
            detail={`${t('overviewRunning')}: ${runningCount} · ${t('overviewWarnings')}: ${operationWarnings}`}
            attention={runningCount > 0 || operationWarnings > 0}
            actionLabel={t('viewDetails')}
            onClick={() => onNavigate('logs')}
          />
        </div>
      </section>
    </div>
  )
}

function AttentionRow({
  label,
  value,
  detail,
  attention,
  actionLabel,
  onClick,
}: {
  label: string
  value: number
  detail: string
  attention: boolean
  actionLabel: string
  onClick: () => void
}) {
  return (
    <div className="dsh-rtm-attention-row">
      <StateDot state={attention ? 'warning' : 'done'} size={7} />
      <div className="dsh-rtm-attention-main">
        <strong>{label}</strong>
        <span>{detail}</span>
      </div>
      <span className={attention ? 'dsh-rtm-attention-count is-attention' : 'dsh-rtm-attention-count'}>{value}</span>
      <Button size="sm" variant="ghost" onClick={onClick}>{actionLabel}</Button>
    </div>
  )
}
