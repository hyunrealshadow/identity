import { StateEffect, StateField, type Extension, type Range } from '@identity/codemirror/state';
import { Decoration, EditorView, WidgetType, type DecorationSet } from '@identity/codemirror/view';
import type { ComponentDiagnostic } from '../types';

/** Recompute diagnostics after fields, locale, or messages change. */
export const refreshDiagnostics = StateEffect.define<null>();

/**
 * Stop deferring the diagnostics at the caret, as when the input loses focus
 * or a submit asks for every error.
 */
export const finishEditing = StateEffect.define<null>();

/**
 * The diagnostics the problem list currently explains, and the one the
 * pointer or keyboard is on, so their marks in the text stand out with them.
 */
export const setShownDiagnostics = StateEffect.define<{
  shown: readonly ComponentDiagnostic[];
  focused: ComponentDiagnostic | null;
}>();

type DiagnosticsState = {
  diagnostics: readonly ComponentDiagnostic[];
  /**
   * Diagnostics of the text being typed at the caret. They are neither marked
   * nor listed until the caret moves away, the input loses focus, or a submit
   * asks for every error, so an unfinished clause is not reported mid-word.
   */
  deferred: readonly ComponentDiagnostic[];
  editing: boolean;
  shown: readonly ComponentDiagnostic[];
  focused: ComponentDiagnostic | null;
};

/** Diagnostics a user can see now: everything except what is being typed. */
export function visibleDiagnostics(state: DiagnosticsState): ComponentDiagnostic[] {
  return state.diagnostics.filter((diagnostic) => !isIn(state.deferred, diagnostic));
}

/** Diagnostics at a position: inside a range, or right at a missing-value point. */
export function diagnosticsAt(
  diagnostics: readonly ComponentDiagnostic[],
  pos: number
): ComponentDiagnostic[] {
  return diagnostics.filter((diagnostic) =>
    diagnostic.from === diagnostic.to
      ? pos === diagnostic.from
      : pos >= diagnostic.from && pos <= diagnostic.to
  );
}

export function sameDiagnostic(a: ComponentDiagnostic, b: ComponentDiagnostic): boolean {
  return a.from === b.from && a.to === b.to && a.code === b.code;
}

/**
 * Marks diagnostics in the text: a wavy underline for a range, a caret mark
 * for a missing value. Their explanation lives in the input's popover, not in
 * a separate tooltip; `onHover` reports the diagnostics under the pointer.
 */
export function luceneDiagnostics(
  compute: (text: string) => ComponentDiagnostic[],
  onHover: (diagnostics: ComponentDiagnostic[]) => void
): { extension: Extension; field: StateField<DiagnosticsState> } {
  const field = StateField.define<DiagnosticsState>({
    create: (state) => ({
      diagnostics: compute(state.doc.toString()),
      deferred: [],
      editing: false,
      shown: [],
      focused: null
    }),
    update(value, tr) {
      let next = value;
      if (tr.docChanged || tr.effects.some((effect) => effect.is(refreshDiagnostics))) {
        next = { ...next, diagnostics: compute(tr.state.doc.toString()), shown: [], focused: null };
      }
      // Typing, deleting, or completing starts an edit at the caret; moving the
      // caret without changing the text ends it.
      let editing = next.editing;
      if (tr.docChanged) {
        editing = tr.isUserEvent('input') || tr.isUserEvent('delete');
      } else if (tr.selection) {
        editing = false;
      }
      if (tr.effects.some((effect) => effect.is(finishEditing))) {
        editing = false;
      }
      const deferred = editing ? diagnosticsAt(next.diagnostics, tr.state.selection.main.head) : [];
      if (editing !== next.editing || deferred.length !== next.deferred.length || tr.docChanged) {
        next = { ...next, editing, deferred };
      }
      for (const effect of tr.effects) {
        if (effect.is(setShownDiagnostics)) {
          next = { ...next, shown: effect.value.shown, focused: effect.value.focused };
        }
      }
      return next;
    },
    provide: (self) => EditorView.decorations.from(self, buildDecorations)
  });

  let hovered: ComponentDiagnostic[] = [];
  const report = (next: ComponentDiagnostic[]) => {
    const unchanged =
      next.length === hovered.length && next.every((item, index) => sameDiagnostic(item, hovered[index]));
    if (!unchanged) {
      hovered = next;
      onHover(next);
    }
  };

  const pointer = EditorView.domEventHandlers({
    mousemove(event, view) {
      const target = event.target instanceof Element
        ? event.target.closest('.lucene-diagnostic-range, .lucene-diagnostic-point')
        : null;
      if (!target) {
        report([]);
        return false;
      }
      const diagnostics = visibleDiagnostics(view.state.field(field));
      const pos = target.classList.contains('lucene-diagnostic-point')
        ? view.posAtDOM(target)
        : view.posAtCoords({ x: event.clientX, y: event.clientY });
      report(pos === null ? [] : diagnosticsAt(diagnostics, pos));
      return false;
    },
    mouseleave() {
      report([]);
      return false;
    }
  });

  return { extension: [field, pointer], field };
}

function isIn(list: readonly ComponentDiagnostic[], diagnostic: ComponentDiagnostic): boolean {
  return list.some((item) => sameDiagnostic(item, diagnostic));
}

function buildDecorations(state: DiagnosticsState): DecorationSet {
  const ranges: Range<Decoration>[] = [];
  for (const diagnostic of visibleDiagnostics(state)) {
    const classes = [`lucene-diagnostic-${diagnostic.severity}`];
    if (diagnostic.code === 'unknownField') classes.push('lucene-diagnostic-unknown-field');
    if (isIn(state.shown, diagnostic)) classes.push('lucene-diagnostic-shown');
    if (state.focused && sameDiagnostic(state.focused, diagnostic)) {
      classes.push('lucene-diagnostic-focused');
    }
    if (diagnostic.from === diagnostic.to) {
      ranges.push(
        Decoration.widget({ widget: new PointWidget(classes.join(' ')), side: 1 }).range(diagnostic.from)
      );
      continue;
    }
    ranges.push(
      Decoration.mark({ class: `lucene-diagnostic-range ${classes.join(' ')}` }).range(
        diagnostic.from,
        diagnostic.to
      )
    );
  }
  return Decoration.set(ranges, true);
}

class PointWidget extends WidgetType {
  constructor(private readonly classes: string) {
    super();
  }

  eq(other: PointWidget): boolean {
    return other.classes === this.classes;
  }

  toDOM(): HTMLElement {
    const span = document.createElement('span');
    span.className = `lucene-diagnostic-point ${this.classes}`;
    span.setAttribute('aria-hidden', 'true');
    return span;
  }

  ignoreEvent(): boolean {
    return false;
  }
}
