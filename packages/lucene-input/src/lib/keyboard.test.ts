import { acceptCompletion } from '@codemirror/autocomplete';
import { describe, expect, it } from 'vitest';
import { luceneCompletionKeymap } from './keyboard';

describe('lucene editor keyboard behavior', () => {
  it('binds Tab to accepting the active completion', () => {
    expect(luceneCompletionKeymap).toEqual([
      {
        key: 'Tab',
        run: acceptCompletion
      }
    ]);
  });
});
