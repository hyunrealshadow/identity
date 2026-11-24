import { useEffect, useId, useRef, type ReactNode } from 'react'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'
import type { LuceneCompletionOption } from './lib/codemirror/completion'
import type { LuceneProblem, LuceneProblemsState } from './lib/problems'
import type { DiagnosticSeverity } from './lib/types'

export type CompletionDropdownLabels = {
  add: string
  historyHint: string
  problems?: string
  severity?: Partial<Record<DiagnosticSeverity, string>>
}

type CompletionDropdownProps = {
  state: LuceneCompletionDropdownState | null
  labels: CompletionDropdownLabels
  /** Show the Shift+Up / Shift+Down history hint. */
  showHistoryHint?: boolean
  /** Host content at the end of the footer, such as a syntax help link. */
  footer?: ReactNode
  /** Diagnostics to explain above the suggestions. */
  problems?: LuceneProblemsState | null
  /** Element id of the problem list, which the input refers to. */
  problemsId?: string
  onHover: (index: number) => void
  onSelect: (index: number) => void
  onProblemHover?: (index: number) => void
  onProblemSelect?: (index: number) => void
  /** The pointer entered or left the popover. */
  onPointerInside?: (inside: boolean) => void
}

function SeverityIcon({ severity, label }: { severity: DiagnosticSeverity; label?: string }) {
  return (
    <svg
      className={`lucene-problem-icon lucene-problem-icon-${severity}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {severity === 'warning' ? (
        <>
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </>
      ) : (
        <>
          <circle cx="12" cy="12" r="10" />
          {severity === 'error' ? (
            <>
              <path d="M12 8v4" />
              <path d="M12 16h.01" />
            </>
          ) : (
            <>
              <path d="M12 16v-4" />
              <path d="M12 8h.01" />
            </>
          )}
        </>
      )}
    </svg>
  )
}

/** The marked text, drawn with the same underline or caret mark as the input. */
function ProblemExcerpt({ problem }: { problem: LuceneProblem }) {
  const severity = problem.diagnostic.severity
  if (problem.point) {
    return (
      <code className="lucene-problem-excerpt">
        {problem.excerpt}
        <span className={`lucene-diagnostic-point lucene-diagnostic-${severity}`} aria-hidden="true" />
      </code>
    )
  }
  return (
    <code className="lucene-problem-excerpt">
      <span className={`lucene-diagnostic-range lucene-diagnostic-${severity}`}>{problem.excerpt}</span>
    </code>
  )
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
  problems,
  problemsId,
  onHover,
  onSelect,
  onProblemHover,
  onProblemSelect,
  onPointerInside,
}: CompletionDropdownProps) {
  const listboxId = useId()
  const activeOptionRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    activeOptionRef.current?.scrollIntoView({ block: 'nearest' })
  }, [state?.selectedIndex, state?.result.from, state?.result.options.length])

  const shownProblems = problems?.problems ?? []
  const options = state?.result.options ?? []
  if (shownProblems.length === 0 && options.length === 0) {
    return null
  }

  const selectedIndex = state?.selectedIndex ?? -1
  const hasFooter = options.length > 0 && (showHistoryHint || Boolean(footer))

  let currentSection = ''

  return (
    <div
      className="lucene-completion-panel"
      onMouseEnter={() => onPointerInside?.(true)}
      onMouseLeave={() => {
        onProblemHover?.(-1)
        onPointerInside?.(false)
      }}
    >
      {shownProblems.length > 0 ? (
        <div
          className="lucene-problems"
          data-has-options={options.length > 0 ? 'true' : undefined}
        >
          {labels.problems ? (
            <div className="lucene-completion-section" aria-hidden="true">
              {labels.problems}
            </div>
          ) : null}
          <ul id={problemsId} className="lucene-problem-list" aria-live="polite">
            {shownProblems.map((problem, index) => (
              <li key={`${problem.diagnostic.code}-${problem.diagnostic.from}-${problem.diagnostic.to}`}>
                <button
                  type="button"
                  tabIndex={-1}
                  className="lucene-problem"
                  data-severity={problem.diagnostic.severity}
                  data-focused={problems?.focusedIndex === index ? 'true' : undefined}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => onProblemHover?.(index)}
                  onClick={() => onProblemSelect?.(index)}
                >
                  <SeverityIcon
                    severity={problem.diagnostic.severity}
                    label={labels.severity?.[problem.diagnostic.severity]}
                  />
                  {problem.excerpt ? <ProblemExcerpt problem={problem} /> : null}
                  <span className="lucene-problem-message">{problem.diagnostic.message}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {options.length > 0 ? (
      <ul id={listboxId} role="listbox" className="lucene-completion-list">
        {options.map((option, index) => {
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
      ) : null}
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
