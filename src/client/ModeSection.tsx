/** Security mode rows: status dot, expandable link path, deploy/repair actions. */
import { useCallback, useState } from 'react'
import { Button, DisclosureRow, IconAgentPresetOutline16, StateDot } from '@deepseek-ai/dsh-client-ui-primitives'
import type { ModeLinkState, ModeStatus, Translate } from './contracts.js'

function modeDot(state: ModeLinkState): 'done' | 'warning' | 'error' {
  if (state === 'ok') return 'done'
  if (state === 'error') return 'error'
  return 'warning'
}

function modeLabelKey(state: ModeLinkState): 'modeStateOk' | 'modeStateMissing' | 'modeStateStale' | 'modeStateError' {
  if (state === 'ok') return 'modeStateOk'
  if (state === 'missing') return 'modeStateMissing'
  if (state === 'stale') return 'modeStateStale'
  return 'modeStateError'
}

export function ModeSection({
  modes,
  t,
  busy,
  pending,
  onDeploy,
  onRepair,
}: {
  modes: ModeStatus[]
  t: Translate
  busy: boolean
  pending: boolean
  onDeploy: (mode: ModeStatus) => void
  onRepair: (mode: ModeStatus) => void
}) {
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set())

  const toggle = useCallback((id: string) => {
    setOpenIds(current => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  return (
    <section className="dsh-rtm-card">
      <div className="dsh-rtm-section-head">
        <h3 className="dsh-rtm-section-title">{t('modesTitle')}</h3>
      </div>
      {modes.length === 0 ? (
        <p className="dsh-rtm-empty">{t('modesEmpty')}</p>
      ) : (
        <div className="dsh-rtm-modes">
          {modes.map(mode => {
            const labelKey = modeLabelKey(mode.linkState)
            const disabled = busy || pending || mode.linkState === 'ok'
            const state = (
              <span className="dsh-rtm-mode-state">
                <StateDot state={modeDot(mode.linkState)} size={7} />
                <span>{t(labelKey)}</span>
              </span>
            )
            const rowActions = (
              <span className="dsh-rtm-mode-actions">
                {state}
                <Button
                  size="sm"
                  variant="outline"
                  disabled={disabled}
                  onClick={event => {
                    event.stopPropagation()
                    onDeploy(mode)
                  }}
                >
                  {t('modeDeploy')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={disabled}
                  onClick={event => {
                    event.stopPropagation()
                    onRepair(mode)
                  }}
                >
                  {t('modeRepair')}
                </Button>
              </span>
            )
            return (
              <DisclosureRow
                key={mode.id}
                icon={<IconAgentPresetOutline16 size={14} />}
                title={mode.name}
                open={openIds.has(mode.id)}
                expandable
                expandOnRowClick
                onToggle={() => toggle(mode.id)}
                collapsedContent={rowActions}
                keepContentWhenOpen
                className="dsh-rtm-disclosure"
              >
                <div className="dsh-rtm-mode-body">
                  <div className="dsh-rtm-mode-summary">
                    <span className="dsh-rtm-muted">{mode.summary}</span>
                  </div>
                  {mode.linkPath !== undefined && mode.linkPath !== '' ? (
                    <div className="dsh-rtm-path">
                      <span>{t('modeLinkPath')}</span>
                      <code title={mode.linkPath}>{mode.linkPath}</code>
                    </div>
                  ) : (
                    <div className="dsh-rtm-path">
                      <span>{t('modeNoPath')}</span>
                    </div>
                  )}
                </div>
              </DisclosureRow>
            )
          })}
        </div>
      )}
    </section>
  )
}
