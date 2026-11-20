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
  #selectedIndex = 0;
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
      const normalizedQuery = nextResult.query.trim().toLowerCase();
      nextResult.options = nextResult.options.filter(
        (option) => option.apply.toLowerCase() !== normalizedQuery
      );

      if (!nextResult.options.length) {
        this.close();
        return;
      }

      this.#result = nextResult;
      this.#selectedIndex = Math.min(this.#selectedIndex, nextResult.options.length - 1);
      this.#sync();
    });
  }

  accept(): boolean {
    if (!this.#view || !this.#result) {
      return false;
    }

    const option = this.#result.options[this.#selectedIndex];
    if (!option) {
      return false;
    }

    this.#view.dispatch({
      changes: {
        from: this.#result.from,
        to: this.#result.to,
        insert: option.apply
      },
      selection: {
        anchor: this.#result.from + option.apply.length
      }
    });
    this.close();
    return true;
  }

  close(): boolean {
    if (!this.#result) {
      return false;
    }

    this.#requestId += 1;
    this.#result = undefined;
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
    this.#selectedIndex = (this.#selectedIndex + step + count) % count;
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
