import { describe, expect, it } from 'vitest';
import { buildLuceneSyntaxTree } from './syntax-tree';

describe('lucene syntax tree', () => {
  it('builds a nested tree for fields, explicit operators, implicit operators, and negation', () => {
    const tree = buildLuceneSyntaxTree("author:jo or ' ' and b author:!c and not c !d");

    expect(tree.type).toBe('Query');
    expect(collect(tree, 'Node').map((node) => node.children?.[0]?.value)).toEqual(['author', 'author']);
    expect(collect(tree, 'BinaryExpression').map((node) => node.operator)).toContain('IMPLICIT');
    expect(collect(tree, 'BinaryExpression').map((node) => node.operator)).toContain('or');
    expect(collect(tree, 'BinaryExpression').map((node) => node.operator)).toContain('and');
    expect(collect(tree, 'NotExpression').map((node) => node.operator)).toContain('!');
    expect(collect(tree, 'FieldTermNotExpression').map((node) => node.operator)).toContain('!');
  });

  it('marks missing operands in the tree', () => {
    expect(buildLuceneSyntaxTree('author:1 && or a')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'or',
          children: [
            {
              type: 'BinaryExpression',
              operator: '&&',
              children: [{ type: 'Node' }, { type: 'Missing' }]
            },
            { type: 'SearchTerm', value: 'a' }
          ]
        }
      ]
    });
  });

  it('keeps field to ranges inside the field node', () => {
    expect(buildLuceneSyntaxTree('published_on:[2024-01-01 to 2024-12-31]')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [
            { type: 'Field', value: 'published_on' },
            {
              type: 'FieldRangeExpression',
              operator: 'to',
              children: [
                { type: 'DateTerm', value: '2024-01-01' },
                { type: 'DateTerm', value: '2024-12-31' }
              ]
            }
          ]
        }
      ]
    });
  });

  it('keeps wildcard range endpoints inside the field node', () => {
    expect(buildLuceneSyntaxTree('published_on:[* TO now/d]')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [
            { type: 'Field', value: 'published_on' },
            {
              type: 'FieldRangeExpression',
              operator: 'TO',
              children: [{ type: 'WildcardTerm', value: '*' }, { type: 'DateMathTerm', value: 'now/d' }]
            }
          ]
        }
      ]
    });
  });

  it('normalizes quoted date field values to date terms', () => {
    expect(buildLuceneSyntaxTree('created_at:"2026-05-14"', [{ name: 'created_at', type: 'date' }])).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'created_at' }, { type: 'DateTerm', value: '2026-05-14' }]
        }
      ]
    });
  });

  it('keeps date math, date, time, and datetime strings as dedicated term nodes', () => {
    expect(buildLuceneSyntaxTree('created_at:now-5m published_on:2026-05-14')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'IMPLICIT',
          children: [
            {
              type: 'Node',
              children: [{ type: 'Field', value: 'created_at' }, { type: 'DateMathTerm', value: 'now-5m' }]
            },
            {
              type: 'Node',
              children: [{ type: 'Field', value: 'published_on' }, { type: 'DateTerm', value: '2026-05-14' }]
            }
          ]
        }
      ]
    });

    expect(buildLuceneSyntaxTree('12:30:57 2026-05-15T10:30:57Z')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'IMPLICIT',
          children: [
            { type: 'TimeTerm', value: '12:30:57' },
            { type: 'DateTimeTerm', value: '2026-05-15T10:30:57Z' }
          ]
        }
      ]
    });
  });

  it('resolves date math in typed date and datetime fields', () => {
    const tree = buildLuceneSyntaxTree('published_on:now/d created_at:now-5m', [
      { name: 'published_on', type: 'date' },
      { name: 'created_at', type: 'datetime' }
    ]);

    expect(collect(tree, 'DateTerm')[0]).toMatchObject({
      type: 'DateTerm',
      value: expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/)
    });
    expect(collect(tree, 'DateTimeTerm')[0]).toMatchObject({
      type: 'DateTimeTerm',
      value: expect.stringMatching(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    });
  });

  it('parses quoted local datetime values in datetime fields', () => {
    expect(
      buildLuceneSyntaxTree('created_at:"2026-05-15 10:21:43"', [{ name: 'created_at', type: 'datetime' }])
    ).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'created_at' }, { type: 'DateTimeTerm', value: '2026-05-15 10:21:43' }]
        }
      ]
    });
  });

  it('keeps unquoted local datetime input as independent date and time terms', () => {
    expect(
      buildLuceneSyntaxTree('created_at:2026-05-15 10:30:57', [{ name: 'created_at', type: 'datetime' }])
    ).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'IMPLICIT',
          children: [
            {
              type: 'Node',
              children: [{ type: 'Field', value: 'created_at' }, { type: 'DateTerm', value: '2026-05-15' }]
            },
            { type: 'TimeTerm', value: '10:30:57' }
          ]
        }
      ]
    });
  });

  it('uses the date part when a date field is given a quoted local datetime', () => {
    expect(
      buildLuceneSyntaxTree('created_at:"2026-05-14 10:00:00"', [{ name: 'created_at', type: 'date' }])
    ).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'created_at' }, { type: 'DateTerm', value: '2026-05-14' }]
        }
      ]
    });
  });

  it('normalizes quoted and unquoted search terms to the same value', () => {
    expect(buildLuceneSyntaxTree('author:john author:"john" "hello world"')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'IMPLICIT',
          children: [
            {
              type: 'BinaryExpression',
              operator: 'IMPLICIT',
              children: [
                {
                  type: 'Node',
                  children: [{ type: 'Field', value: 'author' }, { type: 'SearchTerm', value: 'john' }]
                },
                {
                  type: 'Node',
                  children: [{ type: 'Field', value: 'author' }, { type: 'SearchTerm', value: 'john' }]
                }
              ]
            },
            { type: 'SearchTerm', value: 'hello world' }
          ]
        }
      ]
    });
  });

  it('unescapes spaces in unquoted search terms', () => {
    expect(buildLuceneSyntaxTree(String.raw`title:hello\ world`)).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'title' }, { type: 'SearchTerm', value: 'hello world' }]
        }
      ]
    });
  });

  it('uses escaped spaces to parse unquoted local datetime values as one term', () => {
    expect(
      buildLuceneSyntaxTree(String.raw`created_at:2026-05-15\ 10:30:57`, [{ name: 'created_at', type: 'datetime' }])
    ).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'created_at' }, { type: 'DateTimeTerm', value: '2026-05-15 10:30:57' }]
        }
      ]
    });
  });

  it('unescapes quoted search term values', () => {
    expect(buildLuceneSyntaxTree(String.raw`title:"John \"Johnny\" Appleseed" author:'Jane O\'Connor'`)).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'BinaryExpression',
          operator: 'IMPLICIT',
          children: [
            {
              type: 'Node',
              children: [{ type: 'Field', value: 'title' }, { type: 'SearchTerm', value: 'John "Johnny" Appleseed' }]
            },
            {
              type: 'Node',
              children: [{ type: 'Field', value: 'author' }, { type: 'SearchTerm', value: "Jane O'Connor" }]
            }
          ]
        }
      ]
    });
  });
  it('reads prefix operators, exclusive ranges, fuzzy and boost suffixes', () => {
    const tree = buildLuceneSyntaxTree('-a +b c~2 (d)^3 published_on:{now-1d TO now] title:-x');

    expect(collect(tree, 'NotExpression').map((node) => node.operator)).toEqual(['-']);
    expect(collect(tree, 'RequiredExpression').map((node) => node.operator)).toEqual(['+']);
    expect(collect(tree, 'FuzzyExpression')).toMatchObject([
      { operator: '~2', children: [{ type: 'SearchTerm', value: 'c' }] }
    ]);
    expect(collect(tree, 'BoostExpression')).toMatchObject([
      { operator: '^3', children: [{ type: 'GroupExpression' }] }
    ]);
    expect(collect(tree, 'FieldRangeExpression')).toMatchObject([{ inclusive: [false, true] }]);
    expect(collect(tree, 'SearchTerm').map((node) => node.value)).toContain('-x');
    expect(collect(tree, 'UnparsedTokens')).toEqual([]);
  });

  it('keeps dashes inside values and date math', () => {
    const tree = buildLuceneSyntaxTree('a-b published_on:[now-1d TO now]');
    expect(collect(tree, 'NotExpression')).toEqual([]);
    expect(collect(tree, 'SearchTerm').map((node) => node.value)).toContain('a-b');
  });

  it('parses ? wildcards and comparisons or ranges inside field groups', () => {
    expect(buildLuceneSyntaxTree('author:fo?')).toMatchObject({
      type: 'Query',
      children: [
        {
          type: 'Node',
          children: [{ type: 'Field', value: 'author' }, { type: 'WildcardTerm', value: 'fo?' }]
        }
      ]
    });

    const groupedComparison = buildLuceneSyntaxTree('score:(>=10 OR <5)', [{ name: 'score', type: 'number' }]);
    expect(collect(groupedComparison, 'FieldComparisonExpression').map((node) => node.operator)).toEqual(['>=', '<']);
    expect(collect(groupedComparison, 'UnparsedTokens')).toEqual([]);

    const groupedRange = buildLuceneSyntaxTree('published_on:([2024-01-01 TO 2024-12-31])', [
      { name: 'published_on', type: 'date' }
    ]);
    expect(collect(groupedRange, 'FieldRangeExpression')).toHaveLength(1);
    expect(collect(groupedRange, 'UnparsedTokens')).toEqual([]);
  });
});

function collect(tree: ReturnType<typeof buildLuceneSyntaxTree>, type: string): ReturnType<typeof buildLuceneSyntaxTree>[] {
  const nodes = tree.type === type ? [tree] : [];
  for (const child of tree.children ?? []) {
    nodes.push(...collect(child, type));
  }

  return nodes;
}
