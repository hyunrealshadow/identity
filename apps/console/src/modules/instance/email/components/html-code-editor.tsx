import { html } from '@codemirror/lang-html'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { Annotation, Compartment, EditorState } from '@codemirror/state'
import { EditorView, placeholder as placeholderText } from '@codemirror/view'
import { cn } from '@identity/ui/lib/utils'
import { tags } from '@lezer/highlight'
import { basicSetup } from 'codemirror'
import { useEffect, useRef } from 'react'

/** Marks changes that came from the `value` prop rather than the user. */
const external = Annotation.define<boolean>()

// Colors are variables so the same highlighter follows the light and dark themes.
const highlight = HighlightStyle.define([
  { tag: [tags.tagName, tags.angleBracket], color: 'var(--cm-tag)' },
  { tag: tags.attributeName, color: 'var(--cm-attribute)' },
  { tag: [tags.attributeValue, tags.string], color: 'var(--cm-string)' },
  { tag: [tags.comment, tags.meta, tags.documentMeta], color: 'var(--cm-comment)', fontStyle: 'italic' },
  { tag: [tags.keyword, tags.propertyName], color: 'var(--cm-keyword)' },
  { tag: [tags.number, tags.atom, tags.bool, tags.unit], color: 'var(--cm-number)' },
  { tag: tags.invalid, color: 'var(--destructive)' },
])

const theme = EditorView.theme({
  '&': {
    '--cm-tag': 'oklch(0.5 0.17 255)',
    '--cm-attribute': 'oklch(0.52 0.15 300)',
    '--cm-string': 'oklch(0.5 0.13 150)',
    '--cm-comment': 'var(--muted-foreground)',
    '--cm-keyword': 'oklch(0.55 0.16 25)',
    '--cm-number': 'oklch(0.55 0.13 60)',
    height: '28rem',
    fontSize: '0.75rem',
    color: 'var(--foreground)',
    backgroundColor: 'transparent',
  },
  '.dark &': {
    '--cm-tag': 'oklch(0.75 0.12 250)',
    '--cm-attribute': 'oklch(0.78 0.11 305)',
    '--cm-string': 'oklch(0.78 0.12 150)',
    '--cm-keyword': 'oklch(0.75 0.13 25)',
    '--cm-number': 'oklch(0.8 0.11 70)',
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

type HtmlCodeEditorProps = {
  id: string
  labelId: string
  value: string
  onChange: (value: string) => void
  readOnly?: boolean
  disabled?: boolean
  invalid?: boolean
  describedBy?: string
  placeholder?: string
  className?: string
}

function accessibility({ id, labelId, invalid, describedBy, readOnly, disabled }: HtmlCodeEditorProps) {
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

/** An HTML source editor with highlighting, line numbers and bracket matching. */
export function HtmlCodeEditor(props: HtmlCodeEditorProps) {
  const { value, onChange, invalid, disabled, placeholder, className } = props
  const parent = useRef<HTMLDivElement | null>(null)
  const view = useRef<EditorView | null>(null)
  const config = useRef(new Compartment())
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange
  const propsRef = useRef(props)
  propsRef.current = props

  useEffect(() => {
    if (!parent.current) return
    const editor = new EditorView({
      parent: parent.current,
      state: EditorState.create({
        doc: propsRef.current.value,
        extensions: [
          basicSetup,
          html({ autoCloseTags: true }),
          syntaxHighlighting(highlight),
          theme,
          EditorView.lineWrapping,
          placeholder ? placeholderText(placeholder) : [],
          config.current.of(accessibility(propsRef.current)),
          EditorView.updateListener.of((update) => {
            if (!update.docChanged) return
            if (update.transactions.some((transaction) => transaction.annotation(external))) return
            onChangeRef.current(update.state.doc.toString())
          }),
        ],
      }),
    })
    view.current = editor
    return () => {
      editor.destroy()
      view.current = null
    }
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
      className={cn(
        'overflow-hidden rounded-md border border-input bg-transparent shadow-xs transition-[color,box-shadow] dark:bg-input/30',
        'focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50',
        'data-invalid:border-destructive data-invalid:ring-3 data-invalid:ring-destructive/20 dark:data-invalid:ring-destructive/40',
        'data-disabled:cursor-not-allowed data-disabled:opacity-50',
        className,
      )}
    />
  )
}
