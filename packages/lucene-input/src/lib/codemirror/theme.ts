import { EditorView } from '@codemirror/view';

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
      minHeight: '34px'
    },
    // Text entry: an I-beam across the whole field, including the placeholder.
    '.cm-scroller, .cm-content': {
      cursor: 'text'
    },
    '.cm-content[aria-disabled="true"]': {
      cursor: 'not-allowed'
    },
    '.cm-content': {
      padding: '7px 10px',
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
    },
    // Diagnostic marks.
    '.lucene-diagnostic-range': {
      textDecorationLine: 'underline',
      textDecorationStyle: 'wavy',
      textDecorationColor: 'var(--destructive)',
      textDecorationSkipInk: 'none',
      textUnderlineOffset: '3px'
    },
    '.lucene-diagnostic-range.lucene-diagnostic-warning': {
      textDecorationColor: '#d97706'
    },
    '.lucene-diagnostic-range.lucene-diagnostic-info': {
      textDecorationColor: 'var(--primary)'
    },
    '.lucene-diagnostic-point': {
      position: 'relative'
    },
    '.lucene-diagnostic-point::after': {
      borderBottom: '4px solid var(--destructive)',
      borderLeft: '4px solid transparent',
      borderRight: '4px solid transparent',
      bottom: '-4px',
      content: '""',
      height: '0',
      left: '0',
      position: 'absolute',
      transform: 'translateX(-50%)',
      width: '0'
    },
    '.lucene-diagnostic-point.lucene-diagnostic-warning::after': {
      borderBottomColor: '#d97706'
    },
    '.lucene-diagnostic-point.lucene-diagnostic-info::after': {
      borderBottomColor: 'var(--primary)'
    },
    // Hover explanation: matches the shared shadcn Tooltip (inverted, text-xs,
    // rounded-md) and keeps CodeMirror's arrow on the side facing the text.
    '.cm-tooltip.cm-tooltip-hover:has(.lucene-diagnostic-tooltip)': {
      backgroundColor: 'var(--foreground)',
      border: '0',
      borderRadius: 'calc(var(--radius, 0.625rem) - 2px)',
      color: 'var(--background)',
      fontFamily: 'var(--font-sans, inherit)',
      maxWidth: '20rem',
      zIndex: '50'
    },
    // CodeMirror anchors to the text line; clear the input's border and padding.
    '.cm-tooltip-below.cm-tooltip-hover:has(.lucene-diagnostic-tooltip)': {
      marginTop: '6px'
    },
    '.cm-tooltip-above.cm-tooltip-hover:has(.lucene-diagnostic-tooltip)': {
      marginTop: '-6px'
    },
    '.lucene-diagnostic-tooltip': {
      display: 'grid',
      gap: '2px',
      fontSize: '0.75rem',
      lineHeight: '1rem',
      padding: '6px 12px'
    },
    '.cm-tooltip-below .cm-tooltip-arrow:before, .cm-tooltip-below .cm-tooltip-arrow:after': {
      borderBottomColor: 'var(--foreground)'
    },
    '.cm-tooltip-above .cm-tooltip-arrow:before, .cm-tooltip-above .cm-tooltip-arrow:after': {
      borderTopColor: 'var(--foreground)'
    },
    '.lucene-diagnostic-unknown-field': {
      backgroundColor: 'color-mix(in oklab, var(--destructive) 12%, transparent)'
    }
  });
}
