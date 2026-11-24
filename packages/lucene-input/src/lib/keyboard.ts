import { acceptCompletion } from '@identity/codemirror/autocomplete';
import type { KeyBinding } from '@identity/codemirror/view';

export const luceneCompletionKeymap: KeyBinding[] = [
  {
    key: 'Tab',
    run: acceptCompletion
  }
];
