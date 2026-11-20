import { useEffect, useRef, useState } from 'react'
import { CompletionDropdown } from './CompletionDropdown'
import type { LuceneCompletionDropdownState } from './lib/codemirror/completion-dropdown'
import { createLuceneEditor, type LuceneEditorHandle } from './lib/codemirror'
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
  id?: string
  className?: string
}

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

  return (
    <div id={id} className={className ? `lucene-input-root ${className}` : 'lucene-input-root'}>
      <div ref={hostRef} className="lucene-input-editor" />
      <CompletionDropdown
        state={completionState}
        onHover={(index) => handleRef.current?.hoverCompletion(index)}
        onSelect={(index) => handleRef.current?.selectCompletion(index)}
      />
    </div>
  )
}
