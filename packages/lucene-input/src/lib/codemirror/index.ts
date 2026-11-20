import { Compartment, EditorState, Prec, type Extension } from '@codemirror/state';
import { EditorView, keymap, placeholder } from '@codemirror/view';
import { getLuceneCompletions } from './completion';
import {
  LuceneCompletionDropdown,
  type LuceneCompletionDropdownState
} from './completion-dropdown';
import { luceneDiagnostics, refreshDiagnostics, setDiagnosticTooltip } from './diagnostics';
import { luceneEditorTheme } from './theme';
import { getLuceneDiagnostics } from '../diagnostics';
import { FieldCompletionController } from '../field-completion';
import { preventNewlineKeymap, sanitizeSingleLineValue, singleLineTransactions } from '../single-line';
import { luceneSyntaxHighlighting } from '../syntax-highlighting';
import type { ComponentDiagnostic, LuceneField, LuceneInputMessages } from '../types';

export type LuceneEditorConfig = {
  parent: HTMLElement;
  value: string;
  placeholder?: string;
  ariaLabel?: string;
  disabled?: boolean;
  readOnly?: boolean;
  fields?: LuceneField[];
  disallowUnknownFields?: boolean;
  locale?: string;
  timeZone?: string;
  messages?: LuceneInputMessages;
  onChange?: (value: string) => void;
  onSubmit?: (value: string) => void;
  onDiagnostics?: (diagnostics: ComponentDiagnostic[]) => void;
  onCompletionChange?: (state: LuceneCompletionDropdownState | null) => void;
  /** Show diagnostics in a hover tooltip (default true). */
  diagnosticTooltip?: boolean;
};

export type LuceneEditorHandle = {
  view: EditorView;
  setValue(value: string): void;
  setFields(fields: LuceneField[]): void;
  setDisallowUnknownFields(disallowUnknownFields: boolean): void;
  setLocale(locale: string): void;
  setTimeZone(timeZone: string | undefined): void;
  setMessages(messages: LuceneInputMessages | undefined): void;
  setPlaceholder(placeholder: string): void;
  setDisabled(disabled: boolean): void;
  setReadOnly(readOnly: boolean): void;
  setAriaLabel(ariaLabel: string | undefined): void;
  setDiagnosticTooltip(enabled: boolean): void;
  hoverCompletion(index: number): void;
  selectCompletion(index: number): void;
  closeCompletion(): boolean;
  destroy(): void;
};

export function createLuceneEditor(config: LuceneEditorConfig): LuceneEditorHandle {
  let fields = config.fields ?? [];
  let disallowUnknownFields = config.disallowUnknownFields ?? false;
  let locale = config.locale ?? 'en';
  let timeZone = config.timeZone;
  let messages = config.messages;
  let isDisabled = Boolean(config.disabled);
  let isReadOnly = Boolean(config.readOnly);

  const initialValue = sanitizeSingleLineValue(config.value);
  const completionController = new FieldCompletionController(fields, locale, messages);
  // The error tooltip and the completion menu both open below the text, so the
  // tooltip only shows while the host allows it and no completion is open.
  let hostTooltip = config.diagnosticTooltip ?? true;
  let completionOpen = false;
  let destroyed = false;
  let editorView: EditorView | null = null;
  const syncDiagnosticTooltip = () => {
    // Completion changes arrive during an editor update; dispatch afterwards.
    queueMicrotask(() => {
      if (!destroyed && editorView) {
        editorView.dispatch({
          effects: setDiagnosticTooltip.of(hostTooltip && !completionOpen)
        });
      }
    });
  };

  const completionUi = new LuceneCompletionDropdown((state) => {
    const nextOpen = state !== null;
    if (nextOpen !== completionOpen) {
      completionOpen = nextOpen;
      syncDiagnosticTooltip();
    }
    config.onCompletionChange?.(state);
  });

  const placeholderCompartment = new Compartment();
  const editableCompartment = new Compartment();
  const readOnlyCompartment = new Compartment();
  const ariaCompartment = new Compartment();

  const computeDiagnostics = (text: string) =>
    getLuceneDiagnostics(text, fields, locale, messages, { disallowUnknownFields });

  const notifyDiagnostics = (view: EditorView) => {
    config.onDiagnostics?.(computeDiagnostics(view.state.doc.toString()));
  };

  // Settings changes re-mark the text; document changes refresh on their own.
  const refreshMarks = (view: EditorView) => {
    view.dispatch({ effects: refreshDiagnostics.of(null) });
    notifyDiagnostics(view);
  };

  const buildContentAttributes = (label: string | undefined, disabled: boolean) => {
    const attrs: Record<string, string> = {
      role: 'combobox',
      'aria-autocomplete': 'list'
    };
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
      if (update.docChanged) {
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
          getCompletionSectionLabels(locale),
          locale,
          messages,
          fields,
          timeZone
        )
      );
    }),
    luceneDiagnostics(computeDiagnostics, { tooltip: hostTooltip }),
    luceneEditorTheme()
  ];

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
    setDiagnosticTooltip(enabled: boolean) {
      hostTooltip = enabled;
      syncDiagnosticTooltip();
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
      completionUi.destroy();
      view.destroy();
    }
  };
}

function getCompletionSectionLabels(locale: string): { fields: string; syntax: string; values: string } {
  return locale.startsWith('zh')
    ? { fields: '字段', syntax: '语法', values: '字段值' }
    : { fields: 'Fields', syntax: 'Syntax', values: 'Values' };
}
