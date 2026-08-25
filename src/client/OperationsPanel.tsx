/** Operation log: state, target, detail, progress, cancel/clear controls. */
import { Button, StateDot } from '@deepseek-ai/dsh-client-ui-primitives'
import type { OperationKind, OperationRecord, OperationState, Translate } from './contracts.js'

function opDot(state: OperationState): 'done' | 'warning' | 'ongoing' | 'error' {
  if (state === 'running') return 'ongoing'
  if (state === 'queued') return 'warning'
  if (state === 'done') return 'done'
  if (state === 'warned') return 'warning'
  if (state === 'cancelled') return 'warning'
  return 'error'
}

function opLabelKey(state: OperationState): 'opQueued' | 'opRunning' | 'opDone' | 'opWarned' | 'opFailed' | 'opCancelled' {
  if (state === 'queued') return 'opQueued'
  if (state === 'running') return 'opRunning'
  if (state === 'done') return 'opDone'
  if (state === 'warned') return 'opWarned'
  if (state === 'cancelled') return 'opCancelled'
  return 'opFailed'
}

function kindLabelKey(kind: OperationKind): 'opKindDeployModes' | 'opKindInstall' | 'opKindUpdate' | 'opKindUninstall' | 'opKindRepair' {
  if (kind === 'deploy-modes') return 'opKindDeployModes'
  if (kind === 'install') return 'opKindInstall'
  if (kind === 'update') return 'opKindUpdate'
  if (kind === 'uninstall') return 'opKindUninstall'
  return 'opKindRepair'
}

export function OperationsPanel({
  operations,
  t,
  busy,
  pending,
  onCancel,
  onClear,
}: {
  operations: OperationRecord[]
  t: Translate
  busy: boolean
  pending: boolean
  onCancel: (id: string) => void
  onClear: () => void
}) {
  const settled = operations.filter(op => op.state === 'done' || op.state === 'warned' || op.state === 'failed' || op.state === 'cancelled').length

  return (
    <section className="dsh-rtm-card">
      <div className="dsh-rtm-section-head">
        <h3 className="dsh-rtm-section-title">{t('operationsTitle')}</h3>
        <Button
          size="sm"
          variant="ghost"
          disabled={busy || pending || settled === 0}
          onClick={onClear}
        >
          {t('opClear')}
        </Button>
      </div>
      {operations.length === 0 ? (
        <p className="dsh-rtm-empty">{t('opEmpty')}</p>
      ) : (
        <div className="dsh-rtm-ops">
          {operations.map(op => {
            const cancellable = op.state === 'queued'
            return (
              <div key={op.id} className="dsh-rtm-op">
                <div className="dsh-rtm-op-head">
                  <span className="dsh-rtm-op-state">
                    <StateDot state={opDot(op.state)} size={7} />
                    <span>{t(opLabelKey(op.state))}</span>
                  </span>
                  <span className="dsh-rtm-op-kind">{t(kindLabelKey(op.kind))}</span>
                  <span className="dsh-rtm-op-target" title={op.target}>{op.target}</span>
                  {cancellable && (
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={pending}
                      onClick={() => onCancel(op.id)}
                    >
                      {t('opCancel')}
                    </Button>
                  )}
                </div>
                {op.state === 'running' && (
                  <div className="dsh-rtm-op-foot">
                    <div
                      className={op.percent === null || op.percent === undefined
                        ? 'dsh-rtm-progress-track dsh-rtm-progress--indeterminate'
                        : 'dsh-rtm-progress-track'}
                      role="progressbar"
                      aria-label={t('opProgress')}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={op.percent ?? undefined}
                    >
                      <div
                        className="dsh-rtm-progress-fill"
                        style={op.percent === null || op.percent === undefined ? undefined : { width: `${op.percent}%` }}
                      />
                    </div>
                    {op.percent !== null && op.percent !== undefined && (
                      <span className="dsh-rtm-progress-value">{Math.round(op.percent)}%</span>
                    )}
                  </div>
                )}
                {op.detail !== undefined && op.detail !== '' && (
                  <div className="dsh-rtm-op-detail">{op.detail}</div>
                )}
                {op.error !== undefined && op.error !== '' && (
                  <div className="dsh-rtm-op-error">{t('opError')}: {op.error}</div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}
