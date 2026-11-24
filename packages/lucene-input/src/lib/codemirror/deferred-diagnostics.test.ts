import { describe, expect, it, vi } from 'vitest';
import { createLuceneEditor } from './index';
import type { LuceneProblemsState } from '../problems';

const marks = (parent: HTMLElement) =>
  parent.querySelectorAll('.lucene-diagnostic-range, .lucene-diagnostic-point').length;

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function setup() {
  const parent = document.createElement('div');
  document.body.append(parent);
  let problems: LuceneProblemsState | null = null;
  const handle = createLuceneEditor({
    parent,
    value: '',
    fields: [{ name: 'category' }],
    onProblemsChange: (next) => {
      problems = next;
    }
  });
  const type = (text: string) => {
    const { view } = handle;
    const at = view.state.doc.length;
    view.dispatch({
      changes: { from: at, insert: text },
      selection: { anchor: at + text.length },
      userEvent: 'input.type'
    });
  };
  return { parent, handle, type, problems: () => problems };
}

describe('diagnostics of the text being typed', () => {
  it('are neither marked nor listed while typing, and appear once the caret moves', async () => {
    const { parent, handle, type, problems } = setup();
    handle.view.focus();
    vi.spyOn(handle.view, 'hasFocus', 'get').mockReturnValue(true);

    type('category:');
    await flush();
    expect(marks(parent)).toBe(0);
    expect(problems()).toBeNull();

    // Moving the caret back onto the clause reports it.
    handle.view.dispatch({ selection: { anchor: 4 } });
    handle.view.dispatch({ selection: { anchor: 9 } });
    await flush();
    expect(marks(parent)).toBe(1);
    expect(problems()?.problems.map((problem) => problem.excerpt)).toEqual(['category:']);
    handle.destroy();
  });

  it('are reported when a submit asks for every error', async () => {
    const { parent, handle, type, problems } = setup();
    vi.spyOn(handle.view, 'hasFocus', 'get').mockReturnValue(true);
    type('category:');
    await flush();
    expect(marks(parent)).toBe(0);

    expect(handle.revealProblems()).toBe(true);
    await flush();
    expect(marks(parent)).toBe(1);
    expect(problems()?.source).toBe('submit');
    handle.destroy();
  });

  it('stay reported for text set from outside, such as a shared link', async () => {
    const { parent, handle } = setup();
    handle.setValue('category:');
    await flush();
    expect(marks(parent)).toBe(1);
    handle.destroy();
  });
});
