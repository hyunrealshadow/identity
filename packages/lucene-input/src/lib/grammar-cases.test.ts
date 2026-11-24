import { describe, expect, it } from 'vitest';
import { getLuceneDiagnostics } from './diagnostics';
import cases from './grammar-cases.json';
import { buildLuceneSyntaxTree } from './syntax-tree';
import type { LuceneField, LuceneSyntaxFeature, LuceneSyntaxTree } from './types';

/**
 * The cases the server's audit query parser also runs, so the input and the
 * server agree on what a query means and which queries are invalid.
 */

type Shape =
  | { and: Shape[] }
  | { or: Shape[] }
  | { not: Shape }
  | { field: string; value: string }
  | { text: string };

const fields = cases.fields as LuceneField[];
const disabledSyntax = cases.disabledSyntax as LuceneSyntaxFeature[];

/** The query's meaning, or null when the tree marks a missing or unparsed part. */
function shape(query: string): Shape | null {
  const tree = buildLuceneSyntaxTree(query);
  if (has(tree, 'Missing') || has(tree, 'UnparsedTokens') || tree.children?.length !== 1) {
    return null;
  }
  return toShape(tree.children[0], undefined);
}

function has(tree: LuceneSyntaxTree, type: string): boolean {
  return tree.type === type || Boolean(tree.children?.some((child) => has(child, type)));
}

function toShape(node: LuceneSyntaxTree, field: string | undefined): Shape {
  const children = node.children ?? [];
  switch (node.type) {
    case 'BinaryExpression': {
      const kind = /^(OR|\|\|)$/i.test(node.operator ?? '') ? 'or' : 'and';
      const items = children.flatMap((child) => {
        const item = toShape(child, field);
        return kind in item ? (item as Record<typeof kind, Shape[]>)[kind] : [item];
      });
      return kind === 'or' ? { or: items } : { and: items };
    }
    case 'NotExpression':
    case 'FieldTermNotExpression':
      return { not: toShape(children[0], field) };
    case 'GroupExpression':
      return toShape(children[0], field);
    case 'Node':
      return toShape(children[1], children[0].value);
    default:
      return field ? { field, value: node.value ?? '' } : { text: node.value ?? '' };
  }
}

function valid(query: string): boolean {
  const diagnostics = getLuceneDiagnostics(query, fields, 'en', undefined, { disabledSyntax });
  return shape(query) !== null && diagnostics.every((item) => item.severity !== 'error');
}

describe('shared grammar cases', () => {
  it.each(cases.valid)('accepts $query', ({ query, ...expected }) => {
    expect(valid(query)).toBe(true);
    if ('tree' in expected) {
      expect(shape(query)).toEqual(expected.tree);
    }
  });

  it.each(cases.invalid)('rejects %s', (query) => {
    expect(valid(query)).toBe(false);
  });
});
