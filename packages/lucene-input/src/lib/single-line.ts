import { EditorState, type Extension, type Transaction } from '@identity/codemirror/state';
import type { KeyBinding } from '@identity/codemirror/view';

export function sanitizeSingleLineValue(value: string): string {
  return value.replace(/\r?\n|\r/g, ' ');
}

export const preventNewlineKeymap: KeyBinding[] = [
  {
    key: 'Enter',
    run: () => true
  },
  {
    key: 'Shift-Enter',
    run: () => true
  }
];

export function singleLineTransactions(): Extension {
  return EditorState.transactionFilter.of((transaction) => {
    if (!transaction.docChanged) {
      return transaction;
    }

    const nextValue = transaction.newDoc.toString();
    const sanitized = sanitizeSingleLineValue(nextValue);
    if (nextValue === sanitized) {
      return transaction;
    }

    return replaceDocument(transaction, sanitized);
  });
}

function replaceDocument(transaction: Transaction, value: string) {
  return {
    changes: {
      from: 0,
      to: transaction.startState.doc.length,
      insert: value
    },
    selection: {
      anchor: Math.min(value.length, transaction.newSelection.main.head)
    }
  };
}
