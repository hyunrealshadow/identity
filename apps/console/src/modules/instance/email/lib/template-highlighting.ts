import { RangeSetBuilder, type Extension } from '@identity/codemirror/state'
import {
  Decoration,
  type DecorationSet,
  EditorView,
  ViewPlugin,
  type ViewUpdate,
} from '@identity/codemirror/view'

/**
 * Highlighting for the template language inside email HTML: `{{ … }}`
 * expressions, `{% … %}` statements and `{# … #}` comments stand out from the
 * surrounding markup, and their contents are colored by role.
 */

export type TemplateTokenType =
  | 'delimiter'
  | 'keyword'
  | 'variable'
  | 'function'
  | 'string'
  | 'number'
  | 'operator'
  | 'comment'

export interface TemplateToken {
  type: TemplateTokenType
  from: number
  to: number
}

export interface TemplateBlock {
  kind: 'expression' | 'statement' | 'comment'
  from: number
  to: number
  tokens: TemplateToken[]
}

const KEYWORDS = new Set([
  'if', 'elif', 'else', 'endif', 'for', 'in', 'endfor', 'break', 'continue',
  'set', 'set_global', 'with', 'endwith', 'block', 'endblock', 'extends',
  'include', 'import', 'as', 'macro', 'endmacro', 'filter', 'endfilter',
  'raw', 'endraw', 'and', 'or', 'not', 'is', 'true', 'false', 'True', 'False',
  'none', 'ignore', 'missing', 'loop',
])

const OPENERS: Record<string, { close: string; kind: TemplateBlock['kind'] }> = {
  '{{': { close: '}}', kind: 'expression' },
  '{%': { close: '%}', kind: 'statement' },
  '{#': { close: '#}', kind: 'comment' },
}

/** Find every template block in `text`. An unclosed block runs to the end. */
export function findTemplateBlocks(text: string): TemplateBlock[] {
  const blocks: TemplateBlock[] = []
  let index = 0
  while (index < text.length) {
    const start = text.indexOf('{', index)
    if (start < 0) break
    const opener = OPENERS[text.slice(start, start + 2)]
    if (!opener) {
      index = start + 1
      continue
    }
    const closeAt = findClose(text, start + 2, opener.close, opener.kind !== 'comment')
    const end = closeAt < 0 ? text.length : closeAt + 2
    blocks.push({
      kind: opener.kind,
      from: start,
      to: end,
      tokens: tokenizeBlock(text, start, end, opener.kind, closeAt >= 0),
    })
    index = end
  }
  return blocks
}

/** Where `close` ends the block, skipping quoted strings in code blocks. */
function findClose(text: string, from: number, close: string, code: boolean): number {
  let index = from
  while (index < text.length) {
    const char = text[index]
    if (code && (char === '"' || char === "'" || char === '`')) {
      let end = index + 1
      while (end < text.length && text[end] !== char) end += text[end] === '\\' ? 2 : 1
      index = end + 1
      continue
    }
    if (text.startsWith(close, index)) return index
    index += 1
  }
  return -1
}

function tokenizeBlock(
  text: string,
  from: number,
  to: number,
  kind: TemplateBlock['kind'],
  closed: boolean,
): TemplateToken[] {
  // Delimiters include the whitespace-control dash: `{{-`, `-%}`.
  let open = from + 2
  if (text[open] === '-') open += 1
  let close = closed ? to - 2 : to
  if (closed && text[close - 1] === '-' && close - 1 >= open) close -= 1

  const tokens: TemplateToken[] = [{ type: 'delimiter', from, to: open }]
  if (kind === 'comment') {
    if (close > open) tokens.push({ type: 'comment', from: open, to: close })
  } else {
    let afterPipe = false
    let index = open
    while (index < close) {
      const char = text[index]
      if (/\s/.test(char)) {
        index += 1
        continue
      }
      if (char === '"' || char === "'" || char === '`') {
        let end = index + 1
        while (end < close && text[end] !== char) end += text[end] === '\\' ? 2 : 1
        end = Math.min(end + 1, close)
        tokens.push({ type: 'string', from: index, to: end })
        index = end
        afterPipe = false
        continue
      }
      const number = /^\d+(?:\.\d+)?/.exec(text.slice(index, close))
      if (number) {
        tokens.push({ type: 'number', from: index, to: index + number[0].length })
        index += number[0].length
        afterPipe = false
        continue
      }
      const word = /^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*/.exec(text.slice(index, close))
      if (word) {
        const end = index + word[0].length
        const callsFunction = /^\s*\(/.test(text.slice(end, close))
        const type: TemplateTokenType = afterPipe || callsFunction
          ? 'function'
          : KEYWORDS.has(word[0])
            ? 'keyword'
            : 'variable'
        tokens.push({ type, from: index, to: end })
        index = end
        afterPipe = false
        continue
      }
      const operator = /^(?:==|!=|<=|>=|\|\||&&|[|+\-*/%<>=~!(),:[\]])/.exec(text.slice(index, close))
      const length = operator ? operator[0].length : 1
      tokens.push({ type: 'operator', from: index, to: index + length })
      afterPipe = operator?.[0] === '|'
      index += length
    }
  }
  if (close < to) tokens.push({ type: 'delimiter', from: close, to })
  return tokens
}

const blockMarks: Record<TemplateBlock['kind'], Decoration> = {
  expression: Decoration.mark({ class: 'cm-template cm-template-expression' }),
  statement: Decoration.mark({ class: 'cm-template cm-template-statement' }),
  comment: Decoration.mark({ class: 'cm-template cm-template-comment-block' }),
}

const tokenMarks = Object.fromEntries(
  (['delimiter', 'keyword', 'variable', 'function', 'string', 'number', 'operator', 'comment'] as const)
    .map((type) => [type, Decoration.mark({ class: `cm-template-${type}` })]),
) as Record<TemplateTokenType, Decoration>

function decorate(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>()
  for (const block of findTemplateBlocks(view.state.doc.toString())) {
    builder.add(block.from, block.to, blockMarks[block.kind])
    for (const token of block.tokens) {
      if (token.to > token.from) builder.add(token.from, token.to, tokenMarks[token.type])
    }
  }
  return builder.finish()
}

// Template colors win over the HTML colors of the markup they sit in, such as
// an attribute value holding `{{ link }}`, however the marks nest.
const color = (variable: string) => ({ color: `var(${variable}) !important` })

const templateTheme = EditorView.baseTheme({
  '.cm-template': {
    backgroundColor: 'var(--code-template-background)',
    borderRadius: '3px',
  },
  '.cm-template-delimiter, .cm-template-delimiter *': {
    ...color('--code-template'),
    fontWeight: '600',
  },
  '.cm-template-keyword, .cm-template-keyword *': {
    ...color('--code-keyword'),
    fontWeight: '600',
  },
  '.cm-template-variable, .cm-template-variable *': color('--code-template-variable'),
  '.cm-template-function, .cm-template-function *': color('--code-template-function'),
  '.cm-template-string, .cm-template-string *': color('--code-string'),
  '.cm-template-number, .cm-template-number *': color('--code-number'),
  '.cm-template-operator, .cm-template-operator *': color('--code-operator'),
  '.cm-template-comment, .cm-template-comment *': {
    ...color('--code-comment'),
    fontStyle: 'italic',
  },
})

/** Highlight template syntax on top of the HTML language. */
export function templateHighlighting(): Extension {
  return [
    ViewPlugin.fromClass(
      class {
        decorations: DecorationSet
        constructor(view: EditorView) {
          this.decorations = decorate(view)
        }
        update(update: ViewUpdate) {
          if (update.docChanged) this.decorations = decorate(update.view)
        }
      },
      { decorations: (plugin) => plugin.decorations },
    ),
    templateTheme,
  ]
}
