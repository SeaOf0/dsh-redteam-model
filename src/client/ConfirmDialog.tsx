/** Shared confirmation modal for destructive uninstall actions. */
import { Button, Modal } from '@deepseek-ai/dsh-client-ui-primitives'
import type { Translate } from './contracts.js'

export function ConfirmDialog({
  open,
  targets,
  title,
  description,
  confirmLabel,
  cancelLabel,
  busy,
  t,
  onClose,
  onConfirm,
}: {
  open: boolean
  targets: string[]
  title: string
  description: string
  confirmLabel: string
  cancelLabel: string
  busy: boolean
  t: Translate
  onClose: () => void
  onConfirm: () => void
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      closeLabel={cancelLabel}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{cancelLabel}</Button>
          <Button variant="primary" className="dsh-rtm-btn--danger" disabled={busy} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      )}
    >
      <span className="dsh-rtm-muted">{t('confirmTargets')}</span>
      <ul className="dsh-rtm-confirm-list">
        {targets.map(target => <li key={target}>{target}</li>)}
      </ul>
      <p className="dsh-rtm-confirm-note">{t('confirmUninstallDesc')}</p>
    </Modal>
  )
}
