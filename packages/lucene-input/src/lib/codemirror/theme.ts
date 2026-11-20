import { EditorView } from '@codemirror/view';

export function luceneEditorTheme() {
  return EditorView.theme({
    '&': {
      border: '1px solid var(--input, var(--border))',
      borderRadius: 'var(--radius, 0.5rem)',
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
      minHeight: '36px'
    },
    '.cm-content': {
      padding: '7px 12px',
      minHeight: '20px',
      caretColor: 'var(--foreground)'
    },
    '.cm-line': {
      padding: '0'
    },
    '.cm-placeholder': {
      color: 'var(--muted-foreground)'
    },
    '.cm-gutters': {
      display: 'none'
    },
    '.cm-tooltip.cm-tooltip-lint, .cm-tooltip-lint': {
      backgroundColor: 'var(--popover)',
      border: '1px solid var(--border) !important',
      borderRadius: 'var(--radius, 0.5rem)',
      boxShadow: '0 8px 20px rgba(0, 0, 0, 0.16), 0 1px 3px rgba(0, 0, 0, 0.08)',
      color: 'var(--popover-foreground)',
      listStyle: 'none',
      margin: '0',
      fontFamily: 'inherit',
      fontSize: '0.8125rem',
      lineHeight: '1.125rem',
      maxWidth: '520px',
      overflow: 'hidden',
      outline: '0',
      padding: '0',
      zIndex: '40'
    },
    '.cm-tooltip:has(.cm-tooltip-lint)': {
      background: 'transparent',
      border: '0 !important',
      boxShadow: 'none',
      outline: '0',
      overflow: 'visible',
      padding: '0'
    },
    '.cm-tooltip:has(.cm-tooltip-lint)::before, .cm-tooltip:has(.cm-tooltip-lint)::after': {
      borderLeft: '6px solid transparent',
      borderRight: '6px solid transparent',
      content: '""',
      height: '0',
      left: '14px',
      pointerEvents: 'none',
      position: 'absolute',
      width: '0'
    },
    '.cm-tooltip:has(.cm-tooltip-lint)::before': {
      borderBottom: '6px solid var(--border)',
      top: '-6px'
    },
    '.cm-tooltip:has(.cm-tooltip-lint)::after': {
      borderBottom: '6px solid var(--popover)',
      top: '-5px'
    },
    '.cm-tooltip-lint .cm-diagnostic': {
      background: 'transparent',
      borderLeft: '0',
      color: 'inherit',
      display: 'flex',
      gap: '10px',
      margin: '0',
      padding: '8px 12px 8px 0'
    },
    '.cm-tooltip-lint .cm-diagnostic::before': {
      background: 'var(--destructive)',
      content: '""',
      flex: '0 0 4px',
      margin: '-8px 0',
      minHeight: '34px'
    },
    '.cm-tooltip-lint .cm-diagnostic-warning::before': {
      background: '#d97706'
    },
    '.cm-tooltip-lint .cm-diagnostic-info::before': {
      background: 'var(--primary)'
    },
    '.cm-tooltip-lint .cm-diagnosticText': {
      color: 'var(--popover-foreground)'
    },
    '.cm-tooltip-lint .cm-diagnosticSource': {
      color: 'var(--muted-foreground)',
      fontSize: '0.75rem'
    },
    '.cm-tooltip-lint .cm-diagnosticAction': {
      backgroundColor: 'var(--muted)',
      border: '1px solid var(--border)',
      borderRadius: 'calc(var(--radius, 0.5rem) - 2px)',
      color: 'var(--foreground)',
      font: 'inherit',
      padding: '2px 6px',
      cursor: 'pointer'
    },
    '.cm-lintPoint::after': {
      background: 'transparent',
      borderBottom: '4px solid var(--destructive)',
      borderLeft: '4px solid transparent',
      borderRight: '4px solid transparent',
      borderRadius: '0',
      bottom: '-2px',
      height: '0',
      left: '0',
      transform: 'translateX(-50%)',
      zIndex: '2',
      width: '0'
    },
    '.cm-lintPoint-warning::after': {
      borderBottomColor: '#d97706'
    },
    '.cm-lintPoint-info::after': {
      borderBottomColor: 'var(--primary)'
    },
    '.cm-lintRange-active': {
      backgroundColor: 'transparent'
    },
    '.lucene-diagnostic-unknown-field': {
      backgroundColor: 'color-mix(in oklab, var(--destructive) 12%, transparent)'
    },
    '.lucene-diagnostic-missing-value': {
      backgroundColor: 'transparent'
    }
  });
}
