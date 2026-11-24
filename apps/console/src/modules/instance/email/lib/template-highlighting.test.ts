// @vitest-environment node
import { describe, expect, it } from 'vitest'

import { findTemplateBlocks, type TemplateTokenType } from './template-highlighting'

/** Each token's text with its role, in order. */
function roles(text: string) {
  return findTemplateBlocks(text).map((block) => ({
    kind: block.kind,
    text: text.slice(block.from, block.to),
    tokens: block.tokens.map((token): [TemplateTokenType, string] => [
      token.type,
      text.slice(token.from, token.to),
    ]),
  }))
}

describe('template highlighting', () => {
  it('finds expressions inside HTML attributes and text', () => {
    const text = '<a href="{{ link }}">{{ user.name }}</a>'

    expect(roles(text)).toEqual([
      {
        kind: 'expression',
        text: '{{ link }}',
        tokens: [['delimiter', '{{'], ['variable', 'link'], ['delimiter', '}}']],
      },
      {
        kind: 'expression',
        text: '{{ user.name }}',
        tokens: [['delimiter', '{{'], ['variable', 'user.name'], ['delimiter', '}}']],
      },
    ])
  })

  it('tells statements, filters, literals and operators apart', () => {
    const [statement, expression] = roles(
      '{%- if application and expires_in_minutes > 5 -%}{{ email | upper | truncate(length=20) }}',
    )

    expect(statement.kind).toBe('statement')
    expect(statement.tokens).toEqual([
      ['delimiter', '{%-'],
      ['keyword', 'if'],
      ['variable', 'application'],
      ['keyword', 'and'],
      ['variable', 'expires_in_minutes'],
      ['operator', '>'],
      ['number', '5'],
      ['delimiter', '-%}'],
    ])
    expect(expression.tokens).toEqual([
      ['delimiter', '{{'],
      ['variable', 'email'],
      ['operator', '|'],
      ['function', 'upper'],
      ['operator', '|'],
      ['function', 'truncate'],
      ['operator', '('],
      ['variable', 'length'],
      ['operator', '='],
      ['number', '20'],
      ['operator', ')'],
      ['delimiter', '}}'],
    ])
  })

  it('keeps strings and comments whole, even with delimiter characters inside', () => {
    expect(roles('{{ "a }} b" }}{# note {{ x }} #}')).toEqual([
      {
        kind: 'expression',
        text: '{{ "a }} b" }}',
        tokens: [['delimiter', '{{'], ['string', '"a }} b"'], ['delimiter', '}}']],
      },
      {
        kind: 'comment',
        text: '{# note {{ x }} #}',
        tokens: [['delimiter', '{#'], ['comment', ' note {{ x }} '], ['delimiter', '#}']],
      },
    ])
  })

  it('leaves plain braces alone and runs an unclosed block to the end', () => {
    expect(roles('body { color: red } {{ open')).toEqual([
      {
        kind: 'expression',
        text: '{{ open',
        tokens: [['delimiter', '{{'], ['variable', 'open']],
      },
    ])
  })
})
