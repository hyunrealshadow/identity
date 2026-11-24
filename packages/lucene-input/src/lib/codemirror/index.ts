import { Compartment, EditorState, Prec, type Extension } from '@identity/codemirror/state';
import { EditorView, keymap, placeholder } from '@identity/codemirror/view';
import { getLuceneCompletions } from './completion';
import {
  LuceneCompletionDropdown,
  type LuceneCompletionDropdownState
} from './completion-dropdown';
import {
  diagnosticsAt,
  finishEditing,
  luceneDiagnostics,
  visibleDiagnostics,
  refreshDiagnostics,
  sameDiagnostic,
  setShownDiagnostics
} from './diagnostics';
import { describeProblem, type LuceneProblemsState } from '../problems';
import { luceneEditorTheme } from './theme';
import { getLuceneDiagnostics } from '../diagnostics';
import { localizeSyntaxCompletion } from '../i18n';
import { FieldCompletionController } from '../field-completion';
import { preventNewlineKeymap, sanitizeSingleLineValue, singleLineTransactions } from '../single-line';
import { luceneSyntaxHighlighting } from '../syntax-highlighting';
import type { ComponentDiagnostic, LuceneField, LuceneInputMessages, LuceneSyntaxFeature } from '../types';

export type LuceneEditorConfig = {
  parent: HTMLElement;
  value: string;
  placeholder?: string;
  ariaLabel?: string;
  disabled?: boolean;
  readOnly?: boolean;
  fields?: LuceneField[];
  disallowUnknownFields?: boolean;
  /** Syntax the host does not support; the input marks it as an error. */
  disabledSyntax?: readonly LuceneSyntaxFeature[];
  locale?: string;
  timeZone?: string;
  messages?: LuceneInputMessages;
  onChange?: (value: string) => void;
  onSubmit?: (value: string) => void;
  onDiagnostics?: (diagnostics: ComponentDiagnostic[]) => void;
  onCompletionChange?: (state: LuceneCompletionDropdownState | null) => void;
  /** The problems the popover should explain, or null when there are none to show. */
  onProblemsChange?: (state: LuceneProblemsState | null) => void;
  /** Element id of the popover's problem list, for `aria-describedby`. */
  problemsId?: string;
  /** Earlier queries, most recent first, cycled with Shift+Up and Shift+Down. */
  history?: readonly string[];
};

export type LuceneEditorHandle = {
  view: EditorView;
  setValue(value: string): void;
  setFields(fields: LuceneField[]): void;
  setDisallowUnknownFields(disallowUnknownFields: boolean): void;
  setDisabledSyntax(disabledSyntax: readonly LuceneSyntaxFeature[]): void;
  setLocale(locale: string): void;
  setTimeZone(timeZone: string | undefined): void;
  setMessages(messages: LuceneInputMessages | undefined): void;
  setPlaceholder(placeholder: string): void;
  setDisabled(disabled: boolean): void;
  setReadOnly(readOnly: boolean): void;
  setAriaLabel(ariaLabel: string | undefined): void;
  /** List every error, put the caret on the first, and return whether there were any. */
  revealProblems(): boolean;
  /** The pointer moved onto (index) or off (-1) a problem in the popover. */
  hoverProblem(index: number): void;
  /** Move the caret to a problem in the popover. */
  selectProblem(index: number): void;
  /** Whether the pointer is over the popover, which keeps hovered problems open. */
  setPopoverHovered(hovered: boolean): void;
  setHistory(history: readonly string[]): void;
  hoverCompletion(index: number): void;
  selectCompletion(index: number): void;
  closeCompletion(): boolean;
  destroy(): void;
};

export function createLuceneEditor(config: LuceneEditorConfig): LuceneEditorHandle {
  let fields = config.fields ?? [];
  let disallowUnknownFields = config.disallowUnknownFields ?? false;
  let disabledSyntax = config.disabledSyntax ?? [];
  let locale = config.locale ?? 'en';
  let timeZone = config.timeZone;
  let messages = config.messages;
  let isDisabled = Boolean(config.disabled);
  let isReadOnly = Boolean(config.readOnly);
  let history = config.history ?? [];
  // -1 is the query being written; it is kept while browsing history.
  let historyIndex = -1;
  let historyDraft = '';
  let browsingHistory = false;

  const initialValue = sanitizeSingleLineValue(config.value);
  const completionController = new FieldCompletionController(fields, locale, messages);
  let destroyed = false;
  let editorView: EditorView | null = null;

  // What the popover explains: the errors listed by a rejected submit, else
  // the marks under the pointer, else the marks at the caret.
  let submitted = false;
  let pointerProblems: ComponentDiagnostic[] = [];
  let popoverHovered = false;
  let pointerLeaveTimer: ReturnType<typeof setTimeout> | undefined;
  let focusedProblem: ComponentDiagnostic | null = null;
  let lastProblems: LuceneProblemsState | null = null;
  let remarkPending = false;

  const completionUi = new LuceneCompletionDropdown((state) => {
    config.onCompletionChange?.(state);
    syncProblems();
  });

  const currentDiagnostics = (view: EditorView) => view.state.field(diagnosticsField).diagnostics;
  const shownDiagnostics = (view: EditorView) => visibleDiagnostics(view.state.field(diagnosticsField));

  const computeProblems = (view: EditorView): LuceneProblemsState | null => {
    const diagnostics = currentDiagnostics(view);
    let shown: readonly ComponentDiagnostic[] = [];
    let source: LuceneProblemsState['source'] = 'caret';
    if (submitted && view.hasFocus) {
      shown = diagnostics.filter((diagnostic) => diagnostic.severity === 'error');
      source = 'submit';
    }
    if (shown.length === 0 && pointerProblems.length > 0) {
      shown = pointerProblems;
      source = 'pointer';
    }
    // Suggestions at the caret are themselves the way to fix what is there.
    if (shown.length === 0 && view.hasFocus && !isDisabled && !completionUi.isOpen()) {
      shown = diagnosticsAt(shownDiagnostics(view), view.state.selection.main.head);
      source = 'caret';
    }
    if (shown.length === 0) {
      return null;
    }
    const text = view.state.doc.toString();
    const focusedIndex = focusedProblem
      ? shown.findIndex((diagnostic) => sameDiagnostic(diagnostic, focusedProblem!))
      : -1;
    return {
      problems: shown.map((diagnostic) => describeProblem(text, diagnostic)),
      focusedIndex,
      source
    };
  };

  const sameProblems = (a: LuceneProblemsState | null, b: LuceneProblemsState | null) =>
    a === b ||
    (a !== null &&
      b !== null &&
      a.source === b.source &&
      a.focusedIndex === b.focusedIndex &&
      a.problems.length === b.problems.length &&
      a.problems.every(
        (problem, index) =>
          sameDiagnostic(problem.diagnostic, b.problems[index].diagnostic) &&
          problem.diagnostic.message === b.problems[index].diagnostic.message &&
          problem.excerpt === b.problems[index].excerpt
      ));

  // Problems change during editor updates; publish and re-mark afterwards.
  const syncProblems = () => {
    queueMicrotask(() => {
      if (destroyed || !editorView) return;
      const next = computeProblems(editorView);
      if (!remarkPending && sameProblems(next, lastProblems)) return;
      remarkPending = false;
      lastProblems = next;
      const shown = next?.problems.map((problem) => problem.diagnostic) ?? [];
      const focused = next && next.focusedIndex >= 0 ? shown[next.focusedIndex] : null;
      editorView.dispatch({
        effects: [
          setShownDiagnostics.of({ shown, focused }),
          ariaCompartment.reconfigure(
            buildContentAttributes(currentAriaLabel, isDisabled, next ? config.problemsId : undefined)
          )
        ]
      });
      config.onProblemsChange?.(next);
    });
  };

  const { extension: diagnosticsExtension, field: diagnosticsField } = luceneDiagnostics(
    (text) => computeDiagnostics(text),
    (hovered) => {
      clearTimeout(pointerLeaveTimer);
      if (hovered.length > 0) {
        pointerProblems = hovered;
        syncProblems();
        return;
      }
      // Leave time to move from the mark into the popover.
      pointerLeaveTimer = setTimeout(() => {
        if (popoverHovered) return;
        pointerProblems = [];
        syncProblems();
      }, 200);
    }
  );

  const placeholderCompartment = new Compartment();
  const editableCompartment = new Compartment();
  const readOnlyCompartment = new Compartment();
  const ariaCompartment = new Compartment();

  const computeDiagnostics = (text: string) =>
    getLuceneDiagnostics(text, fields, locale, messages, { disallowUnknownFields, disabledSyntax });

  const notifyDiagnostics = (view: EditorView) => {
    config.onDiagnostics?.(computeDiagnostics(view.state.doc.toString()));
  };

  // Settings changes re-mark the text; document changes refresh on their own.
  const refreshMarks = (view: EditorView) => {
    view.dispatch({ effects: refreshDiagnostics.of(null) });
    notifyDiagnostics(view);
  };

  let currentDescribedBy: string | undefined;
  const buildContentAttributes = (
    label: string | undefined,
    disabled: boolean,
    describedBy: string | undefined = currentDescribedBy
  ) => {
    currentDescribedBy = describedBy;
    const attrs: Record<string, string> = {
      role: 'combobox',
      'aria-autocomplete': 'list'
    };
    if (describedBy) {
      attrs['aria-describedby'] = describedBy;
    }
    if (label) {
      attrs['aria-label'] = label;
    }
    if (disabled) {
      attrs['aria-disabled'] = 'true';
    }
    return EditorView.contentAttributes.of(attrs);
  };

  let currentAriaLabel = config.ariaLabel;

  const extensions: Extension[] = [
    singleLineTransactions(),
    Prec.highest(
      keymap.of([
        ...completionUi.keymap(),
        {
          key: 'Enter',
          run: (view) => {
            if (completionUi.acceptKeyboardSelection()) {
              return true;
            }
            completionUi.close();
            config.onSubmit?.(sanitizeSingleLineValue(view.state.doc.toString()));
            return true;
          }
        },
        {
          key: 'Shift-ArrowUp',
          run: (view) => stepHistory(view, 1)
        },
        {
          key: 'Shift-ArrowDown',
          run: (view) => stepHistory(view, -1)
        },
        ...preventNewlineKeymap
      ])
    ),
    luceneSyntaxHighlighting(),
    EditorView.lineWrapping,
    placeholderCompartment.of(placeholder(config.placeholder ?? '')),
    editableCompartment.of(EditorView.editable.of(!isDisabled)),
    readOnlyCompartment.of(EditorState.readOnly.of(isDisabled || isReadOnly)),
    ariaCompartment.of(buildContentAttributes(currentAriaLabel, isDisabled)),
    EditorView.updateListener.of((update) => {
      if (update.docChanged || (update.focusChanged && !update.view.hasFocus)) {
        // Editing or leaving the input ends the list of a rejected submit.
        submitted = false;
      }
      if (
        update.focusChanged &&
        !update.view.hasFocus &&
        update.state.field(diagnosticsField).editing
      ) {
        // Leaving the input reports what was being typed.
        queueMicrotask(() => {
          if (!destroyed) update.view.dispatch({ effects: finishEditing.of(null) });
        });
      }
      const remarked =
        update.docChanged ||
        update.transactions.some((tr) => tr.effects.some((effect) => effect.is(refreshDiagnostics)));
      if (remarked) {
        // Recomputed marks start plain; mark the shown problems again.
        remarkPending = true;
      }
      if (remarked || update.selectionSet || update.focusChanged) {
        syncProblems();
      }

      if (update.docChanged) {
        if (!browsingHistory) {
          historyIndex = -1;
        }
        const nextValue = sanitizeSingleLineValue(update.state.doc.toString());
        config.onChange?.(nextValue);
        notifyDiagnostics(update.view);
      }

      if (isDisabled || isReadOnly) {
        completionUi.close();
        return;
      }

      // Only the user's editing, caret movement, or focus opens suggestions;
      // host-driven refreshes (fields, locale, tooltip) must not reopen a list
      // that was just closed by submitting.
      if (!update.docChanged && !update.selectionSet && !update.focusChanged) {
        return;
      }

      completionUi.update(update.view, () =>
        getLuceneCompletions(
          update.view,
          completionController,
          getCompletionSectionLabels(locale, messages),
          locale,
          messages,
          fields,
          timeZone,
          history
        )
      );
    }),
    diagnosticsExtension,
    luceneEditorTheme()
  ];

  function stepHistory(view: EditorView, step: number): boolean {
    if (isDisabled || isReadOnly || history.length === 0) {
      return false;
    }
    const nextIndex = Math.min(Math.max(historyIndex + step, -1), history.length - 1);
    if (nextIndex === historyIndex) {
      return true;
    }
    if (historyIndex === -1) {
      historyDraft = view.state.doc.toString();
    }
    historyIndex = nextIndex;
    const text = nextIndex === -1 ? historyDraft : sanitizeSingleLineValue(history[nextIndex] ?? '');
    browsingHistory = true;
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: text },
      selection: { anchor: text.length }
    });
    browsingHistory = false;
    completionUi.close();
    return true;
  }

  const view = new EditorView({
    parent: config.parent,
    state: EditorState.create({
      doc: initialValue,
      extensions
    })
  });

  editorView = view;

  queueMicrotask(() => notifyDiagnostics(view));

  return {
    view,
    setValue(value: string) {
      const sanitized = sanitizeSingleLineValue(value);
      const current = view.state.doc.toString();
      if (current === sanitized) {
        return;
      }

      const currentAnchor = view.state.selection.main.anchor;
      const nextAnchor =
        current.length === 0 || currentAnchor >= current.length
          ? sanitized.length
          : Math.min(currentAnchor, sanitized.length);

      view.dispatch({
        changes: { from: 0, to: current.length, insert: sanitized },
        selection: { anchor: nextAnchor }
      });
      notifyDiagnostics(view);
    },
    setFields(nextFields: LuceneField[]) {
      fields = nextFields;
      completionController.setFields(nextFields);
      refreshMarks(view);
    },
    setDisallowUnknownFields(nextDisallowUnknownFields: boolean) {
      disallowUnknownFields = nextDisallowUnknownFields;
      refreshMarks(view);
    },
    setDisabledSyntax(nextDisabledSyntax: readonly LuceneSyntaxFeature[]) {
      disabledSyntax = nextDisabledSyntax;
      refreshMarks(view);
    },
    setLocale(nextLocale: string) {
      locale = nextLocale;
      completionController.setLocale(nextLocale);
      refreshMarks(view);
    },
    setTimeZone(nextTimeZone: string | undefined) {
      timeZone = nextTimeZone;
    },
    setMessages(nextMessages: LuceneInputMessages | undefined) {
      messages = nextMessages;
      completionController.setMessages(nextMessages);
      refreshMarks(view);
    },
    setPlaceholder(nextPlaceholder: string) {
      view.dispatch({
        effects: placeholderCompartment.reconfigure(placeholder(nextPlaceholder))
      });
    },
    setDisabled(nextDisabled: boolean) {
      isDisabled = nextDisabled;
      view.dispatch({
        effects: [
          editableCompartment.reconfigure(EditorView.editable.of(!isDisabled)),
          readOnlyCompartment.reconfigure(EditorState.readOnly.of(isDisabled || isReadOnly)),
          ariaCompartment.reconfigure(buildContentAttributes(currentAriaLabel, isDisabled))
        ]
      });
      if (isDisabled) {
        completionUi.close();
      }
    },
    setReadOnly(nextReadOnly: boolean) {
      isReadOnly = nextReadOnly;
      view.dispatch({
        effects: readOnlyCompartment.reconfigure(EditorState.readOnly.of(isDisabled || isReadOnly))
      });
      if (isReadOnly) {
        completionUi.close();
      }
    },
    setAriaLabel(nextAriaLabel: string | undefined) {
      currentAriaLabel = nextAriaLabel;
      view.dispatch({
        effects: ariaCompartment.reconfigure(buildContentAttributes(currentAriaLabel, isDisabled))
      });
    },
    revealProblems() {
      const errors = currentDiagnostics(view).filter((diagnostic) => diagnostic.severity === 'error');
      if (errors.length === 0) {
        return false;
      }
      submitted = true;
      completionUi.close();
      view.focus();
      view.dispatch({
        selection: { anchor: errors[0].to },
        effects: finishEditing.of(null),
        scrollIntoView: true
      });
      syncProblems();
      return true;
    },
    hoverProblem(index: number) {
      focusedProblem = index >= 0 ? (lastProblems?.problems[index]?.diagnostic ?? null) : null;
      syncProblems();
    },
    selectProblem(index: number) {
      const diagnostic = lastProblems?.problems[index]?.diagnostic;
      if (!diagnostic) {
        return;
      }
      view.focus();
      view.dispatch({ selection: { anchor: diagnostic.to }, scrollIntoView: true });
    },
    setPopoverHovered(hovered: boolean) {
      popoverHovered = hovered;
      if (!hovered && pointerProblems.length > 0) {
        pointerProblems = [];
        focusedProblem = null;
        syncProblems();
      }
    },
    setHistory(nextHistory: readonly string[]) {
      history = nextHistory;
      historyIndex = -1;
    },
    hoverCompletion(index: number) {
      completionUi.hover(index);
    },
    selectCompletion(index: number) {
      completionUi.select(index);
    },
    closeCompletion() {
      return completionUi.close();
    },
    destroy() {
      destroyed = true;
      clearTimeout(pointerLeaveTimer);
      completionUi.destroy();
      view.destroy();
    }
  };
}

function getCompletionSectionLabels(
  locale: string,
  messages: LuceneInputMessages | undefined
): { history: string; fields: string; syntax: string; values: string } {
  return {
    history: localizeSyntaxCompletion('historySection', locale, messages),
    fields: localizeSyntaxCompletion('fieldsSection', locale, messages),
    syntax: localizeSyntaxCompletion('syntaxSection', locale, messages),
    values: localizeSyntaxCompletion('valuesSection', locale, messages)
  };
}
