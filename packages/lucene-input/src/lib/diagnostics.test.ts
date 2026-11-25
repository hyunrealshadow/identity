import { describe, expect, it } from 'vitest';
import { getLuceneDiagnostics } from './diagnostics';
import type { LuceneField } from './types';

const fields: LuceneField[] = [
  { name: 'author' },
  { name: 'title' },
  { name: 'score', type: 'number' },
  { name: 'published_on', type: 'date' },
  { name: 'published_at', type: 'time' },
  { name: 'created_at', type: 'datetime' }
];

describe('lucene diagnostics', () => {
  it('reports unknown fields with localized messages', () => {
    expect(getLuceneDiagnostics('authorx:john', fields, 'zh-CN')).toEqual([
      {
        code: 'unknownField',
        message: '不能使用 "authorx:" 进行搜索',
        severity: 'warning',
        from: 0,
        to: 7,
        params: { field: 'authorx' }
      }
    ]);
  });

  it('reports unknown fields as errors when disallowUnknownFields is enabled', () => {
    expect(getLuceneDiagnostics('authorx:john', fields, 'en', undefined, { disallowUnknownFields: true })).toEqual([
      {
        code: 'unknownField',
        message: 'Cannot search with "authorx:"',
        severity: 'error',
        from: 0,
        to: 7,
        params: { field: 'authorx' }
      }
    ]);
  });

  it('reports unclosed groups', () => {
    expect(getLuceneDiagnostics('author:(john OR jane', fields)).toEqual([
      {
        code: 'unclosedGroup',
        message: 'Add a closing ")" to finish this group',
        severity: 'error',
        from: 7,
        to: 8,
        params: {}
      }
    ]);
  });

  it('reports missing values after a field colon', () => {
    expect(getLuceneDiagnostics('author:', fields)).toEqual([
      {
        code: 'missingToken',
        message: 'Enter search text after author:',
        severity: 'error',
        from: 7,
        to: 7,
        params: { expected: 'field value', field: 'author' }
      }
    ]);
  });

  it('extends missing field value diagnostics across trailing whitespace', () => {
    expect(getLuceneDiagnostics('author:  ', fields)).toEqual([
      {
        code: 'missingToken',
        message: 'Enter search text after author:',
        severity: 'error',
        from: 7,
        to: 9,
        params: { expected: 'field value', field: 'author' }
      }
    ]);
  });

  it('supports consumer message overrides', () => {
    expect(
      getLuceneDiagnostics('bad:value', fields, 'en', {
        diagnostics: {
          unknownField: 'No such field: {field}'
        }
      })[0]?.message
    ).toBe('No such field: bad');
  });

  it('reports consecutive boolean operators as invalid syntax', () => {
    expect(getLuceneDiagnostics('author:1 && or a', fields)).toEqual([
      {
        code: 'unexpectedToken',
        message: '"or" cannot be used here',
        severity: 'error',
        from: 12,
        to: 14,
        params: { token: 'or' }
      }
    ]);
  });

  it('reports trailing boolean operators as missing a term', () => {
    expect(getLuceneDiagnostics('author:1 &&', fields)).toEqual([
      {
        code: 'missingToken',
        message: 'Enter another search condition after &&',
        severity: 'error',
        from: 9,
        to: 11,
        params: { expected: 'term', operator: '&&' }
      }
    ]);
  });

  it('extends trailing boolean operator diagnostics across trailing whitespace', () => {
    expect(getLuceneDiagnostics('author:1 AND ', fields)).toEqual([
      {
        code: 'missingToken',
        message: 'Enter another search condition after AND',
        severity: 'error',
        from: 9,
        to: 13,
        params: { expected: 'term', operator: 'AND' }
      }
    ]);
  });

  it('allows negation after explicit and implicit boolean operators', () => {
    expect(getLuceneDiagnostics("author:jo or ' ' and b author:!c and not c !d", fields)).toEqual([]);
    expect(getLuceneDiagnostics('c !d', fields)).toEqual([]);
    expect(getLuceneDiagnostics('not c not d', fields)).toEqual([]);
    expect(getLuceneDiagnostics('c and !d', fields)).toEqual([]);
    expect(getLuceneDiagnostics('c or !d', fields)).toEqual([]);
  });

  it('allows negated field values', () => {
    expect(getLuceneDiagnostics('author:!c', fields)).toEqual([]);
  });

  it('allows comparison operators for number fields', () => {
    expect(getLuceneDiagnostics('score:>10 score:<=99.5 score:<0 score:>=-2', fields)).toEqual([]);
  });

  it('reports invalid comparison values for number fields', () => {
    expect(getLuceneDiagnostics('score:>=many', fields, 'zh-CN')).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'score 需要输入数字',
        severity: 'error',
        from: 8,
        to: 12,
        params: { field: 'score', expected: 'number' }
      }
    ]);
  });

  it('allows comparison operators for date, time, and datetime fields', () => {
    expect(
      getLuceneDiagnostics(
        'published_on:>=2024-01-01 published_at:<12:30:00 created_at:<="2024-01-01 12:30:00"',
        fields
      )
    ).toEqual([]);
  });

  it('allows date-like fields to use to ranges', () => {
    expect(
      getLuceneDiagnostics(
        'published_on:[2024-01-01 TO 2024-12-31] published_at:[09:00:00 to 18:30:00] created_at:["2024-01-01 09:00:00" To "2024-01-01 18:30:00"]',
        fields
      )
    ).toEqual([]);
  });

  it('requires quotes around datetime values that contain spaces', () => {
    expect(getLuceneDiagnostics('created_at:2024-01-01 12:30:00', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Press Tab to complete the date and time for created_at',
        severity: 'warning',
        from: 11,
        to: 21,
        params: { field: 'created_at', expected: 'datetime', repairable: true }
      }
    ]);
  });

  it('allows single quoted datetime values that contain spaces', () => {
    expect(getLuceneDiagnostics("created_at:'2024-01-01 12:30:00'", fields)).toEqual([]);
  });

  it('allows escaped spaces in unquoted datetime values', () => {
    expect(getLuceneDiagnostics(String.raw`created_at:2024-01-01\ 12:30:00`, fields)).toEqual([]);
  });

  it('allows more clauses after a range', () => {
    for (const query of [
      'created_at:[now-15m TO now] AND author:john',
      'created_at:[now-15m TO now] AND "x"',
      'created_at:["2024-01-01 09:00:00" TO now] OR title:a',
      'published_on:[2024-01-01 TO 2024-12-31] AND NOT title:a',
      '(author:john OR author:jane) AND title:a'
    ]) {
      expect(getLuceneDiagnostics(query, fields), query).toEqual([]);
    }
  });

  it('still checks a range that is followed by more clauses', () => {
    expect(getLuceneDiagnostics('created_at:[yesterday TO now] AND title:a', fields)).toEqual([
      expect.objectContaining({
        code: 'invalidFieldValue',
        from: 12,
        to: 21,
        params: expect.objectContaining({ field: 'created_at' })
      })
    ]);
  });

  it('allows boolean operators after quoted datetime values', () => {
    expect(getLuceneDiagnostics('created_at:"2026-05-15 10:25:57" AND a', fields)).toEqual([]);
  });

  it('allows ISO 8601 datetime values', () => {
    expect(
      getLuceneDiagnostics(
        'created_at:2024-01-01T09:00:00Z created_at:<=2024-01-01T18:30:00+08:00 created_at:[2024-01-01T09:00:00Z TO 2024-01-01T18:30:00Z]',
        fields
      )
    ).toEqual([]);
  });

  it('requires timezone when datetime values use T', () => {
    expect(getLuceneDiagnostics('created_at:2024-01-01T09:00:00', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid datetime for created_at: "YYYY-MM-DD HH:mm:ss", YYYY-MM-DDTHH:mm:ssZ, or now-5m',
        severity: 'error',
        from: 11,
        to: 30,
        params: { field: 'created_at', expected: 'datetime' }
      }
    ]);
  });

  it('rejects timezone when datetime values use a space separator', () => {
    expect(getLuceneDiagnostics('created_at:"2024-01-01 09:00:00Z"', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid datetime for created_at: "YYYY-MM-DD HH:mm:ss", YYYY-MM-DDTHH:mm:ssZ, or now-5m',
        severity: 'error',
        from: 11,
        to: 33,
        params: { field: 'created_at', expected: 'datetime' }
      }
    ]);
  });

  it('allows date math for date and datetime values', () => {
    expect(
      getLuceneDiagnostics(
        'published_on:now/d created_at:now-5m created_at:[now-10m TO now] published_on:[now-7d/d TO now/d]',
        fields
      )
    ).toEqual([]);
  });

  it('rejects old friendly relative date values', () => {
    expect(getLuceneDiagnostics('published_on:today created_at:5min', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid date for published_on: YYYY-MM-DD or now/d',
        severity: 'error',
        from: 13,
        to: 18,
        params: { field: 'published_on', expected: 'date' }
      },
      {
        code: 'invalidFieldValue',
        message: 'Use a valid datetime for created_at: "YYYY-MM-DD HH:mm:ss", YYYY-MM-DDTHH:mm:ssZ, or now-5m',
        severity: 'error',
        from: 30,
        to: 34,
        params: { field: 'created_at', expected: 'datetime' }
      }
    ]);
  });

  it('allows wildcard endpoints in date-like to ranges', () => {
    expect(
      getLuceneDiagnostics(
        'published_on:[* TO now/d] created_at:[now-1h TO *] published_at:[* TO 18:30:00]',
        fields
      )
    ).toEqual([]);
  });

  it('distinguishes date, time, and datetime values', () => {
    expect(getLuceneDiagnostics('published_on:12:30 published_at:2024-01-01 created_at:2024-01-01', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid date for published_on: YYYY-MM-DD or now/d',
        severity: 'error',
        from: 13,
        to: 18,
        params: { field: 'published_on', expected: 'date' }
      },
      {
        code: 'invalidFieldValue',
        message: 'Use a valid time for published_at: HH:mm:ss',
        severity: 'error',
        from: 32,
        to: 42,
        params: { field: 'published_at', expected: 'time' }
      },
      {
        code: 'invalidFieldValue',
        message: 'Press Tab to complete the date and time for created_at',
        severity: 'warning',
        from: 54,
        to: 64,
        params: { field: 'created_at', expected: 'datetime', repairable: true }
      }
    ]);
  });

  it('requires seconds in datetime values', () => {
    expect(getLuceneDiagnostics('created_at:2024-01-01T09:00', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid datetime for created_at: "YYYY-MM-DD HH:mm:ss", YYYY-MM-DDTHH:mm:ssZ, or now-5m',
        severity: 'error',
        from: 11,
        to: 27,
        params: { field: 'created_at', expected: 'datetime' }
      }
    ]);
  });

  it('ignores colons inside quoted strings and structured field values', () => {
    expect(
      getLuceneDiagnostics('author:"a:b" title:"authorx:bad" author:User:1234', fields, 'en', undefined, {
        disallowUnknownFields: true
      })
    ).toEqual([]);

    expect(
      getLuceneDiagnostics(
        'created_at:"2026-11-20 10:00:00" AND title:"created_at:not-a-date"',
        fields,
        'en',
        undefined,
        { disallowUnknownFields: true }
      )
    ).toEqual([]);
  });

  it('requires seconds in time values', () => {
    expect(getLuceneDiagnostics('published_at:09:00', fields)).toEqual([
      {
        code: 'invalidFieldValue',
        message: 'Use a valid time for published_at: HH:mm:ss',
        severity: 'error',
        from: 13,
        to: 18,
        params: { field: 'published_at', expected: 'time' }
      }
    ]);
  });
  it('marks only the syntax a host disables', () => {
    const query = '-a +b c~2 d^3 /e/ created_at:{now-1d TO now}';
    expect(getLuceneDiagnostics(query, fields).filter((item) => item.severity === 'error')).toEqual([]);

    const disabled = getLuceneDiagnostics(query, fields, 'zh-CN', undefined, {
      disabledSyntax: ['prefixOperators', 'exclusiveRanges', 'regex', 'fuzzy', 'boost']
    }).filter((item) => item.code === 'unsupportedSyntax');
    expect(disabled.map((item) => [item.params?.feature, query.slice(item.from, item.to)])).toEqual([
      ['prefixOperators', '-'],
      ['prefixOperators', '+'],
      ['fuzzy', '~2'],
      ['boost', '^3'],
      ['regex', '/e/'],
      ['exclusiveRanges', '{'],
      ['exclusiveRanges', '}']
    ]);
    expect(disabled[0].message).toBe('不支持前缀 "-"，请用 AND、NOT 组合条件');

    const onlyRegex = getLuceneDiagnostics(query, fields, 'en', undefined, { disabledSyntax: ['regex'] });
    expect(onlyRegex.filter((item) => item.code === 'unsupportedSyntax')).toHaveLength(1);
  });

  it('reports text the grammar cannot place', () => {
    expect(getLuceneDiagnostics('author:a )', fields)).toMatchObject([
      { code: 'unexpectedToken', severity: 'error', from: 9, to: 10, params: { token: ')' } }
    ]);
    expect(getLuceneDiagnostics(':a', fields)).toMatchObject([
      { code: 'unexpectedToken', from: 0, to: 1, params: { token: ':' } }
    ]);
  });

  it('ignores parentheses inside quotes or escaped in terms', () => {
    expect(getLuceneDiagnostics('author:"hello (world"', fields)).toEqual([]);
    expect(getLuceneDiagnostics(String.raw`title:a\(b`, fields)).toEqual([]);
  });

  it('reports unclosed quotes, unclosed ranges, missing TO, empty groups, mid-query missing field values, and invalid comparisons', () => {
    expect(getLuceneDiagnostics('author:"hello', fields)).toMatchObject([
      { code: 'missingToken', severity: 'error', params: { expected: 'closing quote', delimiter: '"' } }
    ]);
    expect(getLuceneDiagnostics("author:'hello", fields, 'zh-CN')).toMatchObject([
      {
        code: 'missingToken',
        severity: 'error',
        message: "请添加 ' 来结束这段引号内容",
        params: { expected: 'closing quote', delimiter: "'" }
      }
    ]);
    expect(getLuceneDiagnostics('author:[a TO b', fields, 'zh-CN')).toMatchObject([
      {
        code: 'missingToken',
        severity: 'error',
        message: '请添加 "]" 来结束这个范围',
        params: { expected: 'closing bracket', delimiter: ']' }
      }
    ]);
    expect(getLuceneDiagnostics('published_on:[2024-01-01 2024-12-31]', fields, 'zh-CN')).toMatchObject([
      {
        code: 'missingToken',
        severity: 'error',
        message: '范围的起止值之间请使用 TO',
        params: { expected: 'TO' }
      }
    ]);
    expect(getLuceneDiagnostics('()', fields, 'zh-CN')).toMatchObject([
      {
        code: 'missingToken',
        severity: 'error',
        message: '请在分组内输入搜索条件',
        params: { expected: 'group expression' }
      }
    ]);
    expect(getLuceneDiagnostics('author:()', fields)).toMatchObject([
      { code: 'missingToken', severity: 'error', params: { expected: 'group expression' } }
    ]);
    expect(getLuceneDiagnostics('(author:)', fields)).toMatchObject([
      { code: 'missingToken', severity: 'error', from: 8, to: 8, params: { expected: 'field value', field: 'author' } }
    ]);
    expect(getLuceneDiagnostics('score:> >=10', fields, 'zh-CN')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'missingToken',
          severity: 'error',
          message: '请在 > 后输入比较值',
          params: { expected: 'comparison value', operator: '>' }
        })
      ])
    );
  });

  it('validates multi-step date math and typed values inside field groups', () => {
    expect(getLuceneDiagnostics('created_at:now-1d+2h/d', fields)).toEqual([]);
    expect(getLuceneDiagnostics('created_at:(>=now-7d AND <now)', fields)).toEqual([]);
    expect(getLuceneDiagnostics('created_at:(>=now-7d AND <bad)', fields)).toEqual([
      expect.objectContaining({
        code: 'invalidFieldValue',
        severity: 'error',
        from: 26,
        to: 29,
        params: { field: 'created_at', expected: 'datetime' }
      })
    ]);
  });

  it('requires whitespace between adjacent implicit clauses while allowing tight explicit operators', () => {
    for (const valid of ['foo "bar"', '(author:a) (title:b)', 'a !b', 'a&&b', '!(author:a)', 'author:!c']) {
      expect(getLuceneDiagnostics(valid, fields), valid).toEqual([]);
    }

    for (const invalid of ['foo"bar"', '(author:a)(title:b)', 'a!b', 'author:a(b)']) {
      expect(getLuceneDiagnostics(invalid, fields).some((item) => item.severity === 'error'), invalid).toBe(true);
    }
  });

  it('allows integer proximity on quoted phrases and rejects invalid fuzzy modifiers', () => {
    expect(getLuceneDiagnostics('"hello world"~10', fields)).toEqual([]);

    for (const invalid of ['"hello world"~0.5', 'foo*~1', '(author:a OR title:b)~2']) {
      expect(getLuceneDiagnostics(invalid, fields).some((item) => item.severity === 'error'), invalid).toBe(true);
    }
  });
});
