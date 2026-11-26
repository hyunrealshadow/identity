import { basicSetup } from 'codemirror'
import { Annotation, Compartment, EditorState, type Extension } from '@codemirror/state'
import { EditorView, placeholder as placeholderText } from '@codemirror/view'
import { useEffect, useRef } from 'react'

import { codeHighlighting } from './highlighting'

/** Marks changes that came from the `value` prop rather than the user. */
const external = Annotation.define<boolean>()

const theme = EditorView.theme({
  '&': {
    height: 'var(--code-editor-height, 28rem)',
    fontSize: '0.75rem',
    color: 'var(--foreground)',
    backgroundColor: 'transparent',
  },
  '&.cm-focused': { outline: 'none' },
  '.cm-scroller': {
    fontFamily: 'var(--font-mono, ui-monospace, monospace)',
    lineHeight: '1.25rem',
  },
  '.cm-content': { caretColor: 'var(--foreground)', padding: '0.5rem 0' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--foreground)' },
  '.cm-gutters': {
    backgroundColor: 'var(--muted)',
    color: 'var(--muted-foreground)',
    borderRight: '1px solid var(--border)',
  },
  '.cm-activeLine': { backgroundColor: 'color-mix(in oklab, var(--muted) 60%, transparent)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--accent)', color: 'var(--foreground)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': {
    backgroundColor: 'color-mix(in oklab, var(--ring) 30%, transparent) !important',
  },
  '&.cm-focused .cm-matchingBracket': {
    backgroundColor: 'color-mix(in oklab, var(--ring) 25%, transparent)',
    outline: '1px solid color-mix(in oklab, var(--ring) 60%, transparent)',
  },
  '.cm-foldPlaceholder': {
    backgroundColor: 'var(--muted)',
    border: '1px solid var(--border)',
    color: 'var(--muted-foreground)',
  },
  '.cm-tooltip': {
    backgroundColor: 'var(--popover)',
    color: 'var(--popover-foreground)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
  },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': {
    backgroundColor: 'var(--accent)',
    color: 'var(--accent-foreground)',
  },
  '.cm-panels': { backgroundColor: 'var(--muted)', color: 'var(--foreground)' },
})

export type CodeEditorProps = {
  id: string
  labelId: string
  value: string
  onChange: (value: string) => void
  /** Language support and other editor extensions, fixed for the editor's life. */
  extensions?: Extension
  readOnly?: boolean
  disabled?: boolean
  invalid?: boolean
  describedBy?: string
  placeholder?: string
  /** Classes for the frame around the editor; the host owns its look. */
  className?: string
}

function accessibility({ id, labelId, invalid, describedBy, readOnly, disabled }: CodeEditorProps) {
  const attributes: Record<string, string> = { id, 'aria-labelledby': labelId, 'aria-multiline': 'true' }
  if (invalid) attributes['aria-invalid'] = 'true'
  if (describedBy) attributes['aria-describedby'] = describedBy
  if (readOnly || disabled) attributes['aria-readonly'] = 'true'
  if (disabled) attributes['aria-disabled'] = 'true'
  return [
    EditorView.contentAttributes.of(attributes),
    EditorState.readOnly.of(Boolean(readOnly || disabled)),
    EditorView.editable.of(!disabled),
  ]
}

/**
 * A multi-line source editor with line numbers, bracket matching and the
 * shared syntax colors. Pass the language through `extensions`.
 */
export function CodeEditor(props: CodeEditorProps) {
  const { value, invalid, disabled, placeholder, className } = props
  const parent = useRef<HTMLDivElement | null>(null)
  const view = useRef<EditorView | null>(null)
  const config = useRef(new Compartment())
  const placeholderConfig = useRef(new Compartment())
  const propsRef = useRef(props)

  useEffect(() => {
    propsRef.current = props
  })

  useEffect(() => {
    if (!parent.current) return
    const editor = new EditorView({
      parent: parent.current,
      state: EditorState.create({
        doc: propsRef.current.value,
        extensions: [
          basicSetup,
          propsRef.current.extensions ?? [],
          codeHighlighting(),
          theme,
          EditorView.lineWrapping,
          placeholderConfig.current.of(
            propsRef.current.placeholder
              ? placeholderText(propsRef.current.placeholder)
              : [],
          ),
          config.current.of(accessibility(propsRef.current)),
          EditorView.updateListener.of((update) => {
            if (!update.docChanged) return
            if (update.transactions.some((transaction) => transaction.annotation(external))) return
            propsRef.current.onChange(update.state.doc.toString())
          }),
        ],
      }),
    })
    view.current = editor
    return () => {
      editor.destroy()
      view.current = null
    }
  }, [])

  useEffect(() => {
    view.current?.dispatch({
      effects: placeholderConfig.current.reconfigure(
        placeholder ? placeholderText(placeholder) : [],
      ),
    })
  }, [placeholder])

  // Follow the value when it changes from outside, such as another language.
  useEffect(() => {
    const editor = view.current
    if (!editor) return
    const current = editor.state.doc.toString()
    if (current === value) return
    editor.dispatch({
      changes: { from: 0, to: current.length, insert: value },
      annotations: external.of(true),
    })
  }, [value])

  useEffect(() => {
    view.current?.dispatch({ effects: config.current.reconfigure(accessibility(props)) })
  }, [props.id, props.labelId, props.invalid, props.describedBy, props.readOnly, props.disabled])

  return (
    <div
      ref={parent}
      data-invalid={invalid ? true : undefined}
      data-disabled={disabled ? true : undefined}
      className={className}
    />
  )
}
