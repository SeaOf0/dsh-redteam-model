/** Compact four-card status strip for the Redteam Manager section. */
import type { AdminSummary, Translate } from './contracts.js'

export function StatusSummary({
  summary,
  runningCount,
  t,
}: {
  summary: AdminSummary
  runningCount: number
  t: Translate
}) {
  const modesReady = summary.modesReady === summary.modesTotal
  const pluginsInstalled = summary.pluginsInstalled === summary.pluginsTotal
  const updates = summary.updatesAvailable > 0
  const running = runningCount > 0

  return (
    <div className="dsh-rtm-stats">
      <div className={modesReady ? 'dsh-rtm-stat dsh-rtm-stat--ok' : 'dsh-rtm-stat dsh-rtm-stat--warn'}>
        <span>{t('statModesReady')}</span>
        <strong>{summary.modesReady}/{summary.modesTotal}</strong>
      </div>
      <div className={pluginsInstalled ? 'dsh-rtm-stat dsh-rtm-stat--ok' : 'dsh-rtm-stat dsh-rtm-stat--warn'}>
        <span>{t('statPluginsInstalled')}</span>
        <strong>{summary.pluginsInstalled}/{summary.pluginsTotal}</strong>
      </div>
      <div className={updates ? 'dsh-rtm-stat dsh-rtm-stat--warn' : 'dsh-rtm-stat'}>
        <span>{t('statUpdates')}</span>
        <strong>{summary.updatesAvailable}</strong>
      </div>
      <div className={running ? 'dsh-rtm-stat dsh-rtm-stat--business' : 'dsh-rtm-stat'}>
        <span>{t('statRunning')}</span>
        <strong>{runningCount}</strong>
      </div>
    </div>
  )
}
