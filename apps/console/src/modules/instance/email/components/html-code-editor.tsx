import { CodeEditor, type CodeEditorProps } from '@identity/codemirror'
import { html } from '@identity/codemirror/lang-html'
import { cn } from '@identity/ui/lib/utils'

import { templateHighlighting } from '../lib/template-highlighting'

// Created once: the editor keeps its extensions for its whole life.
const templateHtml = [html({ autoCloseTags: true }), templateHighlighting()]

type HtmlCodeEditorProps = Omit<CodeEditorProps, 'extensions'>

/** The email template body: HTML with template syntax highlighted. */
export function HtmlCodeEditor({ className, ...props }: HtmlCodeEditorProps) {
  return (
    <CodeEditor
      {...props}
      extensions={templateHtml}
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
