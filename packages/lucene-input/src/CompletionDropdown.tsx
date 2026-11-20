import { useEffect, useId, useRef } from 'react'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'

type CompletionDropdownProps = {
  state: LuceneCompletionDropdownState | null
  onHover: (index: number) => void
  onSelect: (index: number) => void
}

export function CompletionDropdown({ state, onHover, onSelect }: CompletionDropdownProps) {
  const listboxId = useId()
  const activeOptionRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    activeOptionRef.current?.scrollIntoView({ block: 'nearest' })
  }, [state?.selectedIndex, state?.result.from, state?.result.options.length])

  if (!state || state.result.options.length === 0) {
    return null
  }

  const { result, selectedIndex, anchor } = state
  const activeOption = result.options[selectedIndex]

  let currentSection = ''

  return (
    <div
      className="lucene-completion-panel"
      style={{
        left: `${Math.min(anchor.left, 360)}px`,
        top: `${anchor.bottom + 4}px`,
      }}
    >
      <ul
        id={listboxId}
        role="listbox"
        className="lucene-completion-list"
      >
        {result.options.map((option, index) => {
          const showSection = option.section !== currentSection
          if (showSection) {
            currentSection = option.section
          }
          const isSelected = index === selectedIndex

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
                className="lucene-completion-option"
                onMouseDown={(event) => event.preventDefault()}
                onMouseEnter={() => onHover(index)}
                onClick={() => onSelect(index)}
              >
                <span className="lucene-completion-label">{option.label}</span>
                {option.detail ? (
                  <span className="lucene-completion-detail">{option.detail}</span>
                ) : null}
              </button>
            </li>
          )
        })}
      </ul>
      {activeOption?.info ? (
        <div className="lucene-completion-info" aria-live="polite">
          {activeOption.info}
        </div>
      ) : null}
    </div>
  )
}
