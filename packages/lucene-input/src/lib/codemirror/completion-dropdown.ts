import type { EditorView, KeyBinding } from '@codemirror/view';
import type { LuceneCompletionResult } from './completion';

export type CompletionAnchor = {
  left: number;
  top: number;
  bottom: number;
};

export type LuceneCompletionDropdownState = {
  result: LuceneCompletionResult;
  selectedIndex: number;
  anchor: CompletionAnchor;
};

export class LuceneCompletionDropdown {
  #onStateChange: (state: LuceneCompletionDropdownState | null) => void;
  #view: EditorView | undefined;
  #result: LuceneCompletionResult | undefined;
  // -1: nothing highlighted. Enter submits the query unless an option was
  // chosen with the arrow keys (`#keyboardSelected`); hover only highlights.
  #selectedIndex = -1;
  #keyboardSelected = false;
  // The edit made by accepting a value must not reopen the list.
  #skipNextUpdate = false;
  #requestId = 0;

  constructor(onStateChange: (state: LuceneCompletionDropdownState | null) => void) {
    this.#onStateChange = onStateChange;
  }

  keymap(): KeyBinding[] {
    return [
      {
        key: 'ArrowDown',
        run: () => this.#move(1)
      },
      {
        key: 'ArrowUp',
        run: () => this.#move(-1)
      },
      {
        key: 'Tab',
        run: () => this.accept()
      },
      {
        key: 'Escape',
        run: () => this.close()
      }
    ];
  }

  isOpen(): boolean {
    return Boolean(this.#result && this.#result.options.length > 0);
  }

  hover(index: number) {
    if (!this.#result || index < 0 || index >= this.#result.options.length) {
      return;
    }
    this.#selectedIndex = index;
    this.#keyboardSelected = false;
    this.#sync();
  }

  select(index: number) {
    if (!this.#result || index < 0 || index >= this.#result.options.length) {
      return;
    }
    this.#selectedIndex = index;
    this.accept();
  }

  update(view: EditorView, getCompletions: () => Promise<LuceneCompletionResult | null>) {
    this.#view = view;

    if (this.#skipNextUpdate) {
      this.#skipNextUpdate = false;
      this.close();
      return;
    }

    if (!view.hasFocus || !view.state.selection.main.empty) {
      this.close();
      return;
    }

    const requestId = ++this.#requestId;
    void getCompletions().then((result) => {
      if (requestId !== this.#requestId) {
        return;
      }

      if (!result?.options.length) {
        this.close();
        return;
      }

      const nextResult: LuceneCompletionResult = {
        ...result,
        query: this.#view?.state.doc.sliceString(result.from, result.to) ?? ''
      };
      // Keep an exact match, ranked first, so a complete value reads as valid;
      // close when it is the only option, since there is nothing to add.
      const normalizedQuery = nextResult.query.trim().toLowerCase();
      const isExact = (option: { apply: string }) =>
        normalizedQuery !== '' && option.apply.toLowerCase() === normalizedQuery;
      nextResult.options = [
        ...nextResult.options.filter(isExact),
        ...nextResult.options.filter((option) => !isExact(option))
      ];

      if (!nextResult.options.length || nextResult.options.every(isExact)) {
        this.close();
        return;
      }

      const previous = this.#result;
      const sameList =
        previous !== undefined &&
        previous.from === nextResult.from &&
        previous.query === nextResult.query &&
        previous.options.length === nextResult.options.length;
      this.#result = nextResult;
      if (!sameList) {
        this.#selectedIndex = -1;
        this.#keyboardSelected = false;
      }
      this.#sync();
    });
  }

  /** Enter: accept only an option chosen with the arrow keys. */
  acceptKeyboardSelection(): boolean {
    return this.#keyboardSelected && this.#selectedIndex >= 0 ? this.accept() : false;
  }

  /** Tab and click: accept the highlighted option, or the first one. */
  accept(): boolean {
    if (!this.#view || !this.#result) {
      return false;
    }

    const option = this.#result.options[Math.max(this.#selectedIndex, 0)];
    if (!option) {
      return false;
    }

    const { from, to, query } = this.#result;
    const view = this.#view;
    // Close before inserting: the insertion requests the next suggestions
    // (values after a field), which closing afterwards would discard.
    this.close();
    // A value completes its clause; a field or operator leads to further suggestions.
    this.#skipNextUpdate = option.kind === 'value' && option.apply !== query;

    view.dispatch({
      changes: { from, to, insert: option.apply },
      selection: { anchor: from + option.apply.length }
    });
    return true;
  }

  close(): boolean {
    if (!this.#result) {
      return false;
    }

    this.#requestId += 1;
    this.#result = undefined;
    this.#selectedIndex = -1;
    this.#keyboardSelected = false;
    this.#sync();
    return true;
  }

  destroy() {
    this.#requestId += 1;
    this.#result = undefined;
    this.#view = undefined;
    this.#onStateChange(null);
  }

  #move(step: number): boolean {
    if (!this.#result) {
      return false;
    }

    const count = this.#result.options.length;
    this.#selectedIndex =
      this.#selectedIndex < 0
        ? step > 0
          ? 0
          : count - 1
        : (this.#selectedIndex + step + count) % count;
    this.#keyboardSelected = true;
    this.#sync();
    return true;
  }

  #sync() {
    if (!this.#result || !this.#view) {
      this.#onStateChange(null);
      return;
    }

    const anchor = computeAnchor(this.#view, this.#result.from);
    this.#onStateChange({
      result: this.#result,
      selectedIndex: this.#selectedIndex,
      anchor
    });
  }
}

function computeAnchor(view: EditorView, pos: number): CompletionAnchor {
  try {
    const domRect = view.dom.getBoundingClientRect();
    const coords = view.coordsAtPos(pos);
    if (!coords) {
      return { left: 0, top: domRect.height, bottom: domRect.height };
    }
    return {
      left: Math.max(0, coords.left - domRect.left),
      top: Math.max(0, coords.top - domRect.top),
      bottom: Math.max(0, coords.bottom - domRect.top)
    };
  } catch {
    return { left: 0, top: 36, bottom: 36 };
  }
}
