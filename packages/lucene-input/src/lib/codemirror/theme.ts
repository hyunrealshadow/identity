import { EditorView } from '@identity/codemirror/view';

export function luceneEditorTheme() {
  return EditorView.theme({
    // Matches the shared Input: 36px border-box height and the `md` radius.
    '&': {
      border: '1px solid var(--input, var(--border))',
      borderRadius: 'calc(var(--radius, 0.625rem) - 2px)',
      color: 'var(--foreground)',
      fontSize: '0.875rem',
      lineHeight: '1.25rem',
      overflow: 'visible',
      position: 'relative',
      backgroundColor: 'var(--background)',
      transition: 'border-color 150ms ease, box-shadow 150ms ease'
    },
    '&.cm-focused': {
      borderColor: 'var(--ring)',
      boxShadow: '0 0 0 3px color-mix(in oklab, var(--ring) 30%, transparent)',
      outline: 'none'
    },
    '&[aria-disabled="true"]': {
      opacity: '0.5',
      cursor: 'not-allowed'
    },
    '.cm-activeLine': {
      backgroundColor: 'transparent'
    },
    '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': {
      backgroundColor: 'color-mix(in oklab, var(--primary) 22%, transparent)'
    },
    '.cm-scroller': {
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
      lineHeight: '1.25rem',
      minHeight: '34px',
      // A one-line field never scrolls; marks must not create a scrollbar.
      overflow: 'hidden'
    },
    // Text entry: an I-beam across the whole field, including the placeholder.
    '.cm-scroller, .cm-content': {
      cursor: 'text'
    },
    '.cm-content[aria-disabled="true"]': {
      cursor: 'not-allowed'
    },
    '.cm-content': {
      padding: '7px calc(10px + var(--lucene-trailing-width, 0px)) 7px 10px',
      minHeight: '20px',
      caretColor: 'var(--foreground)'
    },
    '.cm-line': {
      padding: '0'
    },
    // CodeMirror's zero-width buffer beside widgets (the missing-value marker)
    // would otherwise sit on the baseline and grow the line past 20px.
    '.cm-line .cm-widgetBuffer': {
      verticalAlign: 'top'
    },
    // Prose hint, set like the shared Input's placeholder: the monospace stack's
    // CJK fallback glyphs sit visibly high in the 20px line.
    '.cm-placeholder': {
      color: 'var(--muted-foreground)',
      fontFamily: 'var(--font-sans, sans-serif)'
    },
    '.cm-gutters': {
      display: 'none'
    }
  });
}
