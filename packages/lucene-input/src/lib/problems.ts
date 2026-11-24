import type { ComponentDiagnostic } from './types';

/** One diagnostic as the popover lists it, with the text it is about. */
export type LuceneProblem = {
  diagnostic: ComponentDiagnostic;
  /** The marked text, or for a missing value the text just before it. */
  excerpt: string;
  /** A missing value, marked with a caret instead of an underline. */
  point: boolean;
};

export type LuceneProblemsState = {
  problems: LuceneProblem[];
  /** The problem under the pointer in the popover, or -1. */
  focusedIndex: number;
  /**
   * Why they are shown: the caret is on them, the pointer is on their marks,
   * or a rejected submit listed every error.
   */
  source: 'caret' | 'pointer' | 'submit';
};

const MAX_EXCERPT = 32;

export function describeProblem(text: string, diagnostic: ComponentDiagnostic): LuceneProblem {
  const point = diagnostic.from === diagnostic.to;
  let excerpt: string;
  if (point) {
    const before = text.slice(0, diagnostic.from).trimEnd();
    excerpt = before.slice(before.search(/\S+$/) >= 0 ? before.search(/\S+$/) : before.length);
    if (excerpt.length > MAX_EXCERPT) excerpt = `…${excerpt.slice(-MAX_EXCERPT + 1)}`;
  } else {
    excerpt = text.slice(diagnostic.from, diagnostic.to);
    if (excerpt.length > MAX_EXCERPT) excerpt = `${excerpt.slice(0, MAX_EXCERPT - 1)}…`;
  }
  return { diagnostic, excerpt, point };
}
