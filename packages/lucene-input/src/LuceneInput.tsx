import { useEffect, useRef, useState, type ReactNode } from 'react'
import { CompletionDropdown } from './CompletionDropdown'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'
import { createLuceneEditor, type LuceneEditorHandle } from './lib/codemirror'
import { localizeSyntaxCompletion } from './lib/i18n'
import type { ComponentDiagnostic, LuceneField, LuceneInputMessages } from './lib/types'

export type LuceneInputProps = {
  value: string
  onChange: (value: string) => void
  onSubmit?: (value: string) => void
  onDiagnostics?: (diagnostics: ComponentDiagnostic[]) => void
  fields?: LuceneField[]
  disallowUnknownFields?: boolean
  locale?: string
  timeZone?: string
  messages?: LuceneInputMessages
  placeholder?: string
  disabled?: boolean
  readOnly?: boolean
  ariaLabel?: string
  /** Explain diagnostics in a hover tooltip; turn off while the host already shows them. */
  diagnosticTooltip?: boolean
  /** Earlier queries, most recent first: offered on an empty input and cycled with Shift+Up/Down. */
  history?: readonly string[]
  /** Host content at the end of the suggestion panel footer, such as syntax help. */
  completionFooter?: ReactNode
  id?: string
  className?: string
}

const NO_HISTORY: readonly string[] = []

export function LuceneInput({
  value,
  onChange,
  onSubmit,
  onDiagnostics,
  fields = [],
  disallowUnknownFields = false,
  locale = 'en',
  timeZone,
  messages,
  placeholder = '',
  disabled = false,
  readOnly = false,
  ariaLabel,
  diagnosticTooltip = true,
  history = NO_HISTORY,
  completionFooter,
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
      locale,
      timeZone,
      messages,
      diagnosticTooltip,
      history,
      onChange: (nextValue) => onChangeRef.current(nextValue),
      onSubmit: (currentValue) => onSubmitRef.current?.(currentValue),
      onDiagnostics: (nextDiagnostics) => onDiagnosticsRef.current?.(nextDiagnostics),
      onCompletionChange: setCompletionState,
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
    handleRef.current?.setDiagnosticTooltip(diagnosticTooltip)
  }, [diagnosticTooltip])

  useEffect(() => {
    handleRef.current?.setHistory(history)
  }, [history])

  return (
    <div id={id} className={className ? `lucene-input-root ${className}` : 'lucene-input-root'}>
      <div ref={hostRef} className="lucene-input-editor" />
      <CompletionDropdown
        state={completionState}
        labels={{
          add: localizeSyntaxCompletion('addAction', locale, messages),
          historyHint: localizeSyntaxCompletion('historyHint', locale, messages),
        }}
        showHistoryHint={history.length > 0}
        footer={completionFooter}
        onHover={(index) => handleRef.current?.hoverCompletion(index)}
        onSelect={(index) => handleRef.current?.selectCompletion(index)}
      />
    </div>
  )
}
