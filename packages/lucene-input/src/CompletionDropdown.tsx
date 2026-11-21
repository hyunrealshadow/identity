import { useEffect, useId, useRef, type ReactNode } from 'react'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'
import type { LuceneCompletionOption } from './lib/codemirror/completion'

export type CompletionDropdownLabels = {
  add: string
  historyHint: string
}

type CompletionDropdownProps = {
  state: LuceneCompletionDropdownState | null
  labels: CompletionDropdownLabels
  /** Show the Shift+Up / Shift+Down history hint. */
  showHistoryHint?: boolean
  /** Host content at the end of the footer, such as a syntax help link. */
  footer?: ReactNode
  onHover: (index: number) => void
  onSelect: (index: number) => void
}

function FilterIcon() {
  return (
    <svg
      className="lucene-completion-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 4h18l-7 8.5V19l-4 2v-8.5z" />
    </svg>
  )
}

function HistoryIcon() {
  return (
    <svg
      className="lucene-completion-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 7v5l3 2" />
    </svg>
  )
}

function optionText(option: LuceneCompletionOption): string {
  return option.kind === 'field' ? option.apply : option.label
}

function optionDescription(option: LuceneCompletionOption): string | undefined {
  // Fields and syntax describe themselves in `info`; values carry their display name in `detail`.
  return option.kind === 'value' ? (option.detail ?? option.info) : (option.info ?? option.detail)
}

export function CompletionDropdown({
  state,
  labels,
  showHistoryHint = false,
  footer,
  onHover,
  onSelect,
}: CompletionDropdownProps) {
  const listboxId = useId()
  const activeOptionRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    activeOptionRef.current?.scrollIntoView({ block: 'nearest' })
  }, [state?.selectedIndex, state?.result.from, state?.result.options.length])

  if (!state || state.result.options.length === 0) {
    return null
  }

  const { result, selectedIndex } = state
  const hasFooter = showHistoryHint || Boolean(footer)

  let currentSection = ''

  return (
    <div className="lucene-completion-panel">
      <ul id={listboxId} role="listbox" className="lucene-completion-list">
        {result.options.map((option, index) => {
          const showSection = option.section !== currentSection
          if (showSection) {
            currentSection = option.section
          }
          const isSelected = index === selectedIndex
          const description = optionDescription(option)

          return (
            <li key={`${option.kind}-${option.label}-${index}`} role="presentation">
              {showSection ? (
                <div className="lucene-completion-section" aria-hidden="true">
                  {option.section}
                </div>
              ) : null}
              <button
                ref={isSelected ? activeOptionRef : null}
                type="button"
                role="option"
                aria-selected={isSelected}
                data-selected={isSelected ? 'true' : 'false'}
                data-kind={option.kind}
                className="lucene-completion-option"
                onMouseDown={(event) => event.preventDefault()}
                onMouseEnter={() => onHover(index)}
                onClick={() => onSelect(index)}
              >
                {option.kind === 'field' ? <FilterIcon /> : null}
                {option.kind === 'history' ? <HistoryIcon /> : null}
                <span className="lucene-completion-label">{optionText(option)}</span>
                {description ? (
                  <span className="lucene-completion-description">{description}</span>
                ) : null}
                <span className="lucene-completion-action" aria-hidden="true">
                  {labels.add}
                </span>
              </button>
            </li>
          )
        })}
      </ul>
      {hasFooter ? (
        <div className="lucene-completion-footer">
          {showHistoryHint ? (
            <span className="lucene-completion-hint">
              <kbd>Shift+↑</kbd>
              <span aria-hidden="true">/</span>
              <kbd>Shift+↓</kbd>
              <span>{labels.historyHint}</span>
            </span>
          ) : (
            <span />
          )}
          {footer ? <span className="lucene-completion-footer-extra">{footer}</span> : null}
        </div>
      ) : null}
    </div>
  )
}
