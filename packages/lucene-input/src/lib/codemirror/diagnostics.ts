import { StateEffect, StateField, type Extension, type Range } from '@codemirror/state';
import {
  Decoration,
  EditorView,
  WidgetType,
  hoverTooltip,
  type DecorationSet
} from '@codemirror/view';
import type { ComponentDiagnostic } from '../types';

/** Recompute diagnostics after fields, locale, or messages change. */
export const refreshDiagnostics = StateEffect.define<null>();

/** Enable or suppress the hover tooltip (e.g. while the host shows the same error). */
export const setDiagnosticTooltip = StateEffect.define<boolean>();

type DiagnosticsState = {
  diagnostics: readonly ComponentDiagnostic[];
  tooltip: boolean;
};

/**
 * Marks diagnostics in the editor and explains them in a hover tooltip placed
 * below the text, with an arrow that follows CodeMirror's actual placement.
 */
export function luceneDiagnostics(
  compute: (text: string) => ComponentDiagnostic[],
  options: { tooltip?: boolean } = {}
): Extension {
  const field = StateField.define<DiagnosticsState>({
    create: (state) => ({
      diagnostics: compute(state.doc.toString()),
      tooltip: options.tooltip ?? true
    }),
    update(value, tr) {
      let next = value;
      for (const effect of tr.effects) {
        if (effect.is(setDiagnosticTooltip) && effect.value !== next.tooltip) {
          next = { ...next, tooltip: effect.value };
        }
      }
      if (tr.docChanged || tr.effects.some((effect) => effect.is(refreshDiagnostics))) {
        next = { ...next, diagnostics: compute(tr.state.doc.toString()) };
      }
      return next;
    },
    provide: (self) =>
      EditorView.decorations.from(self, (value) => buildDecorations(value.diagnostics))
  });

  const tooltip = hoverTooltip(
    (view, pos, side) => {
      const state = view.state.field(field);
      if (!state.tooltip) {
        return null;
      }
      const found = state.diagnostics.filter((diagnostic) =>
        diagnostic.from === diagnostic.to
          ? pos === diagnostic.from || (pos === diagnostic.from - 1 && side > 0)
          : pos >= diagnostic.from && pos <= diagnostic.to
      );
      if (found.length === 0) {
        return null;
      }
      const from = Math.min(...found.map((diagnostic) => diagnostic.from));
      const to = Math.max(...found.map((diagnostic) => diagnostic.to));
      return {
        pos: from,
        end: to,
        above: false,
        arrow: true,
        create: () => ({ dom: renderTooltip(found) })
      };
    },
    {
      hoverTime: 250,
      hideOn: (tr) =>
        tr.effects.some((effect) => effect.is(setDiagnosticTooltip) && !effect.value)
    }
  );

  return [field, tooltip];
}

function buildDecorations(diagnostics: readonly ComponentDiagnostic[]): DecorationSet {
  const ranges: Range<Decoration>[] = [];
  for (const diagnostic of diagnostics) {
    const severity = diagnostic.severity;
    if (diagnostic.from === diagnostic.to) {
      ranges.push(
        Decoration.widget({ widget: new PointWidget(severity), side: 1 }).range(diagnostic.from)
      );
      continue;
    }
    const extra = markClass(diagnostic);
    ranges.push(
      Decoration.mark({
        class: `lucene-diagnostic-range lucene-diagnostic-${severity}${extra ? ` ${extra}` : ''}`
      }).range(diagnostic.from, diagnostic.to)
    );
  }
  return Decoration.set(ranges, true);
}

function markClass(diagnostic: ComponentDiagnostic): string | undefined {
  if (diagnostic.code === 'unknownField') {
    return 'lucene-diagnostic-unknown-field';
  }
  return undefined;
}

class PointWidget extends WidgetType {
  constructor(private readonly severity: ComponentDiagnostic['severity']) {
    super();
  }

  eq(other: PointWidget): boolean {
    return other.severity === this.severity;
  }

  toDOM(): HTMLElement {
    const span = document.createElement('span');
    span.className = `lucene-diagnostic-point lucene-diagnostic-${this.severity}`;
    span.setAttribute('aria-hidden', 'true');
    return span;
  }

  ignoreEvent(): boolean {
    return false;
  }
}

function renderTooltip(diagnostics: readonly ComponentDiagnostic[]): HTMLElement {
  const dom = document.createElement('div');
  dom.className = 'lucene-diagnostic-tooltip';
  dom.setAttribute('role', 'tooltip');
  for (const diagnostic of diagnostics) {
    const line = document.createElement('div');
    line.className = 'lucene-diagnostic-message';
    line.textContent = diagnostic.message;
    dom.append(line);
  }
  return dom;
}
