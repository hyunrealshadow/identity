import {
  useEffect,
  useId,
  useImperativeHandle,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react'
import { CompletionDropdown } from './CompletionDropdown'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'
import { createLuceneEditor, type LuceneEditorHandle } from './lib/codemirror'
import { localizeSyntaxCompletion } from './lib/i18n'
import type { LuceneProblemsState } from './lib/problems'
import type { ComponentDiagnostic, LuceneField, LuceneInputMessages, LuceneSyntaxFeature } from './lib/types'

export type LuceneInputHandle = {
  /**
   * Explain every error in the popover and put the caret on the first, as
   * when a submit is refused. Returns whether there were any.
   */
  revealProblems(): boolean
}

export type LuceneInputProps = {
  ref?: Ref<LuceneInputHandle>
  value: string
  onChange: (value: string) => void
  onSubmit?: (value: string) => void
  onDiagnostics?: (diagnostics: ComponentDiagnostic[]) => void
  fields?: LuceneField[]
  disallowUnknownFields?: boolean
  /** Syntax the backend does not support; the input marks it as an error. */
  disabledSyntax?: readonly LuceneSyntaxFeature[]
  locale?: string
  timeZone?: string
  messages?: LuceneInputMessages
  placeholder?: string
  disabled?: boolean
  readOnly?: boolean
  ariaLabel?: string
  /** Earlier queries, most recent first: offered on an empty input and cycled with Shift+Up/Down. */
  history?: readonly string[]
  /** Host content at the end of the suggestion panel footer, such as syntax help. */
  completionFooter?: ReactNode
  /**
   * Host controls inside the end of the field, such as a clear button. The
   * text keeps clear of them, so showing or hiding one never moves the layout
   * around the input.
   */
  trailing?: ReactNode
  id?: string
  className?: string
}

const NO_HISTORY: readonly string[] = []
const NO_SYNTAX: readonly LuceneSyntaxFeature[] = []

export function LuceneInput({
  ref,
  value,
  onChange,
  onSubmit,
  onDiagnostics,
  fields = [],
  disallowUnknownFields = false,
  disabledSyntax = NO_SYNTAX,
  locale = 'en',
  timeZone,
  messages,
  placeholder = '',
  disabled = false,
  readOnly = false,
  ariaLabel,
  history = NO_HISTORY,
  completionFooter,
  trailing,
  id,
  className,
}: LuceneInputProps) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const handleRef = useRef<LuceneEditorHandle | null>(null)

  const onChangeRef = useRef(onChange)
  const onSubmitRef = useRef(onSubmit)
  const onDiagnosticsRef = useRef(onDiagnostics)

  onChangeRef.current = onChange
  onSubmitRef.current = onSubmit
  onDiagnosticsRef.current = onDiagnostics

  const [completionState, setCompletionState] =
    useState<LuceneCompletionDropdownState | null>(null)
  const [problems, setProblems] = useState<LuceneProblemsState | null>(null)
  const problemsId = useId()
  const rootRef = useRef<HTMLDivElement | null>(null)
  const trailingRef = useRef<HTMLDivElement | null>(null)

  // Reserve the trailing controls' width at the end of the text.
  useEffect(() => {
    const root = rootRef.current
    const element = trailingRef.current
    if (!root) return
    if (!element) {
      root.style.removeProperty('--lucene-trailing-width')
      return
    }
    const update = () =>
      root.style.setProperty('--lucene-trailing-width', `${element.offsetWidth}px`)
    update()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [Boolean(trailing)])

  useImperativeHandle(ref, () => ({
    revealProblems: () => handleRef.current?.revealProblems() ?? false,
  }), [])

  useEffect(() => {
    const parent = hostRef.current
    if (!parent) {
      return
    }

    const handle = createLuceneEditor({
      parent,
      value,
      placeholder,
      ariaLabel,
      disabled,
      readOnly,
      fields,
      disallowUnknownFields,
      disabledSyntax,
      locale,
      timeZone,
      messages,
      history,
      problemsId,
      onChange: (nextValue) => onChangeRef.current(nextValue),
      onSubmit: (currentValue) => onSubmitRef.current?.(currentValue),
      onDiagnostics: (nextDiagnostics) => onDiagnosticsRef.current?.(nextDiagnostics),
      onCompletionChange: setCompletionState,
      onProblemsChange: setProblems,
    })

    handleRef.current = handle

    return () => {
      handleRef.current = null
      handle.destroy()
    }
    // Mount once per component lifetime; dynamic props are pushed via CodeMirror compartments.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    handleRef.current?.setValue(value)
  }, [value])

  useEffect(() => {
    handleRef.current?.setFields(fields)
  }, [fields])

  useEffect(() => {
    handleRef.current?.setDisallowUnknownFields(disallowUnknownFields)
  }, [disallowUnknownFields])

  useEffect(() => {
    handleRef.current?.setDisabledSyntax(disabledSyntax)
  }, [disabledSyntax])

  useEffect(() => {
    handleRef.current?.setLocale(locale)
  }, [locale])

  useEffect(() => {
    handleRef.current?.setTimeZone(timeZone)
  }, [timeZone])

  useEffect(() => {
    handleRef.current?.setMessages(messages)
  }, [messages])

  useEffect(() => {
    handleRef.current?.setPlaceholder(placeholder)
  }, [placeholder])

  useEffect(() => {
    handleRef.current?.setDisabled(disabled)
  }, [disabled])

  useEffect(() => {
    handleRef.current?.setReadOnly(readOnly)
  }, [readOnly])

  useEffect(() => {
    handleRef.current?.setAriaLabel(ariaLabel)
  }, [ariaLabel])

  useEffect(() => {
    handleRef.current?.setHistory(history)
  }, [history])

  return (
    <div
      ref={rootRef}
      id={id}
      className={className ? `lucene-input-root ${className}` : 'lucene-input-root'}
    >
      <div ref={hostRef} className="lucene-input-editor" />
      {trailing ? (
        <div ref={trailingRef} className="lucene-input-trailing">
          {trailing}
        </div>
      ) : null}
      <CompletionDropdown
        state={completionState}
        labels={{
          add: localizeSyntaxCompletion('addAction', locale, messages),
          historyHint: localizeSyntaxCompletion('historyHint', locale, messages),
          problems: localizeSyntaxCompletion('problemsSection', locale, messages),
          severity: {
            error: localizeSyntaxCompletion('errorLabel', locale, messages),
            warning: localizeSyntaxCompletion('warningLabel', locale, messages),
            info: localizeSyntaxCompletion('infoLabel', locale, messages),
          },
        }}
        problems={problems}
        problemsId={problemsId}
        onProblemHover={(index) => handleRef.current?.hoverProblem(index)}
        onProblemSelect={(index) => handleRef.current?.selectProblem(index)}
        onPointerInside={(inside) => handleRef.current?.setPopoverHovered(inside)}
        showHistoryHint={history.length > 0}
        footer={completionFooter}
        onHover={(index) => handleRef.current?.hoverCompletion(index)}
        onSelect={(index) => handleRef.current?.selectCompletion(index)}
      />
    </div>
  )
}
