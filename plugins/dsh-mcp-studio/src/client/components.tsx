/** Shared UI building blocks: fields, pair editor, toggle, store hook. */
import { useEffect, useState, type ReactElement, type ReactNode } from 'react'
import type { Translate } from './contracts.js'
import type { WritableStore } from './store.js'

/** Subscribe a component to one controller store snapshot. */
export function useStoreState<T>(store: WritableStore<T>): T {
  const [state, setState] = useState(() => store.getSnapshot())
  useEffect(() => store.subscribe(() => setState(store.getSnapshot())), [store])
  return state
}

export function Field(props: { label: string; hint?: string; children: ReactNode }): ReactElement {
  return (
    <div className="dsh-mcs-field">
      <span>{props.label}</span>
      {props.children}
      {props.hint !== undefined && <small>{props.hint}</small>}
    </div>
  )
}

export function PairEditor(props: { pairs: Array<{ key: string; value: string }>; t: Translate; onChange(pairs: Array<{ key: string; value: string }>): void }): ReactElement {
  const { t } = props
  return (
    <div className="dsh-mcs-pairs">
      {props.pairs.map((pair, index) => (
        <div key={index} className="dsh-mcs-pairrow">
          <input
            aria-label="key"
            placeholder="KEY"
            value={pair.key}
            onChange={event => props.onChange(props.pairs.map((entry, i) => i === index ? { ...entry, key: event.target.value } : entry))}
          />
          <input
            aria-label="value"
            placeholder={t('pairValuePlaceholder')}
            value={pair.value}
            onChange={event => props.onChange(props.pairs.map((entry, i) => i === index ? { ...entry, value: event.target.value } : entry))}
          />
          <button type="button" className="dsh-mcs-btn dsh-mcs-btn--danger" onClick={() => props.onChange(props.pairs.filter((_, i) => i !== index))}>
            {t('removePair')}
          </button>
        </div>
      ))}
      <button type="button" className="dsh-mcs-btn dsh-mcs-btn--ghost" onClick={() => props.onChange([...props.pairs, { key: '', value: '' }])}>
        {t('addPair')}
      </button>
    </div>
  )
}

export function ToggleSwitch(props: { checked: boolean; label: string; onChange(checked: boolean): void }): ReactElement {
  return (
    <label
      className="dsh-mcs-switch"
      title={props.label}
      onClick={event => event.stopPropagation()}
    >
      <input
        type="checkbox"
        checked={props.checked}
        aria-label={props.label}
        onChange={event => {
          event.stopPropagation()
          props.onChange(event.target.checked)
        }}
        onClick={event => event.stopPropagation()}
      />
      <i />
    </label>
  )
}
