import { describe, expect, it, vi } from 'vitest';
import { diagnosticCodes } from './types';
import type {
  ComponentDiagnostic,
  FieldValueSearch,
  LuceneField,
  LuceneInputMessages
} from './types';

describe('public lucene input types', () => {
  it('supports static fields with optional dynamic value search', async () => {
    const search: FieldValueSearch = vi.fn(async (query, context) => {
      expect(query).toBe('jo');
      expect(context.field.name).toBe('author');
      expect(context.value).toBe('author:jo');
      return [{ label: 'john', value: 'john', detail: 'user' }];
    });

    const field: LuceneField = {
      name: 'author',
      type: 'keyword',
      description: 'Document author',
      search
    };

    await expect(
      field.search?.('jo', {
        field,
        value: 'author:jo',
        position: 9,
        signal: new AbortController().signal
      })
    ).resolves.toEqual([{ label: 'john', value: 'john', detail: 'user' }]);
  });

  it('models localized diagnostics and message overrides', () => {
    const diagnostic: ComponentDiagnostic = {
      code: 'unknownField',
      message: 'Unknown field "bad"',
      severity: 'warning',
      from: 0,
      to: 3,
      params: { field: 'bad' }
    };

    const messages: LuceneInputMessages = {
      diagnostics: {
        unknownField: '未知字段 {field}'
      }
    };

    expect(diagnostic.code).toBe('unknownField');
    expect(messages.diagnostics?.unknownField).toBe('未知字段 {field}');
    expect(diagnosticCodes).toContain('unknownField');
  });
});
