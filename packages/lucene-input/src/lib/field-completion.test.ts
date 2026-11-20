import { describe, expect, it, vi } from 'vitest';
import { FieldCompletionController, getFieldNameCompletions, getFieldValueContext } from './field-completion';
import type { LuceneField } from './types';

describe('field completion', () => {
  it('completes field names from predefined fields', () => {
    const fields: LuceneField[] = [
      { name: 'title', type: 'string' },
      { name: 'author', type: 'keyword', description: 'Document author' },
      { name: 'created_at', type: 'date' }
    ];

    expect(getFieldNameCompletions('aut', 3, fields)).toEqual({
      from: 0,
      options: [{ label: 'author', value: 'author', detail: 'Keyword', description: 'Document author' }]
    });
  });

  it('localizes field type details in field name completions', () => {
    const fields: LuceneField[] = [{ name: 'author', type: 'keyword' }];

    expect(getFieldNameCompletions('aut', 3, fields, 'zh-CN')).toEqual({
      from: 0,
      options: [{ label: 'author', value: 'author', detail: '关键字', description: undefined }]
    });
  });

  it('uses consumer field type label overrides in completions', () => {
    const fields: LuceneField[] = [{ name: 'author', type: 'keyword' }];

    expect(
      getFieldNameCompletions('aut', 3, fields, 'zh-CN', {
        fieldTypes: {
          keyword: '枚举'
        }
      })
    ).toEqual({
      from: 0,
      options: [{ label: 'author', value: 'author', detail: '枚举', description: undefined }]
    });
  });

  it('detects field value context after a known field colon', () => {
    expect(getFieldValueContext('author:jo', 9, [{ name: 'author' }])).toEqual({
      fieldName: 'author',
      query: 'jo',
      from: 7,
      to: 9
    });
  });

  it('runs dynamic value search only for predefined fields with search', async () => {
    const search = vi.fn(async () => [{ label: 'john', value: 'john' }]);
    const controller = new FieldCompletionController([
      { name: 'author', search },
      { name: 'title' }
    ]);

    await expect(controller.completeValue('author:jo', 9)).resolves.toEqual({
      from: 7,
      options: [{ label: 'john', value: 'john' }]
    });

    expect(search).toHaveBeenCalledOnce();
    expect(search).toHaveBeenCalledWith(
      'jo',
      expect.objectContaining({
        field: expect.objectContaining({ name: 'author' }),
        value: 'author:jo',
        position: 9,
        signal: expect.any(AbortSignal)
      })
    );
  });

  it('does not search values for fields without search functions', async () => {
    const controller = new FieldCompletionController([{ name: 'title' }]);

    await expect(controller.completeValue('title:jo', 8)).resolves.toBeNull();
  });

  it('does not search values for unknown fields', async () => {
    const search = vi.fn(async () => [{ label: 'john', value: 'john' }]);
    const controller = new FieldCompletionController([{ name: 'author', search }]);

    await expect(controller.completeValue('unknown:jo', 10)).resolves.toBeNull();
    expect(search).not.toHaveBeenCalled();
  });

  it('aborts stale dynamic value searches', async () => {
    const aborted: boolean[] = [];
    const search = vi.fn(
      async (query: string, context) =>
        new Promise<{ label: string; value: string }[]>((resolve) => {
          if (query === 'jo') {
            resolve([{ label: 'john', value: 'john' }]);
            return;
          }

          context.signal.addEventListener('abort', () => {
            aborted.push(true);
            resolve([]);
          });
        })
    );
    const controller = new FieldCompletionController([{ name: 'author', search }]);

    const first = controller.completeValue('author:j', 8);
    const second = controller.completeValue('author:jo', 9);

    await expect(first).resolves.toBeNull();
    await second;

    expect(aborted).toEqual([true]);
  });
});
