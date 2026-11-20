import { acceptCompletion } from '@codemirror/autocomplete';
import type { KeyBinding } from '@codemirror/view';

export const luceneCompletionKeymap: KeyBinding[] = [
  {
    key: 'Tab',
    run: acceptCompletion
  }
];
