import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'

/**
 * Syntax colors from the shared `--code-*` palette (see `styles.css`), so they
 * follow the light and dark themes.
 */
export const codeHighlightStyle = HighlightStyle.define([
  { tag: [tags.tagName, tags.angleBracket], color: 'var(--code-tag)' },
  { tag: tags.attributeName, color: 'var(--code-attribute)' },
  { tag: [tags.attributeValue, tags.string], color: 'var(--code-string)' },
  { tag: [tags.comment, tags.meta, tags.documentMeta], color: 'var(--code-comment)', fontStyle: 'italic' },
  { tag: [tags.keyword, tags.propertyName], color: 'var(--code-keyword)' },
  { tag: [tags.number, tags.atom, tags.bool, tags.unit], color: 'var(--code-number)' },
  { tag: tags.operator, color: 'var(--code-operator)' },
  { tag: tags.invalid, color: 'var(--destructive)' },
])

export const codeHighlighting = () => syntaxHighlighting(codeHighlightStyle)
