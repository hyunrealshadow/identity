import { linter, type Diagnostic as CodeMirrorDiagnostic } from '@codemirror/lint';
import { Compartment, EditorState, Prec, type Extension } from '@codemirror/state';
import { EditorView, keymap, placeholder } from '@codemirror/view';
import { getLuceneCompletions } from './completion';
import {
  LuceneCompletionDropdown,
  type LuceneCompletionDropdownState
} from './completion-dropdown';
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
  const completionUi = new LuceneCompletionDropdown((state) => {
    config.onCompletionChange?.(state);
  });

  const placeholderCompartment = new Compartment();
  const editableCompartment = new Compartment();
  const readOnlyCompartment = new Compartment();
  const ariaCompartment = new Compartment();

  const notifyDiagnostics = (view: EditorView) => {
    config.onDiagnostics?.(
      getLuceneDiagnostics(view.state.doc.toString(), fields, locale, messages, {
        disallowUnknownFields
      })
    );
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
            if (completionUi.accept()) {
              return true;
            }
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
    linter((view) =>
      getLuceneDiagnostics(view.state.doc.toString(), fields, locale, messages, {
        disallowUnknownFields
      }).map(toCodeMirrorDiagnostic)
    ),
    luceneEditorTheme()
  ];

  const view = new EditorView({
    parent: config.parent,
    state: EditorState.create({
      doc: initialValue,
      extensions
    })
  });

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
      notifyDiagnostics(view);
    },
    setDisallowUnknownFields(nextDisallowUnknownFields: boolean) {
      disallowUnknownFields = nextDisallowUnknownFields;
      notifyDiagnostics(view);
    },
    setLocale(nextLocale: string) {
      locale = nextLocale;
      completionController.setLocale(nextLocale);
      notifyDiagnostics(view);
    },
    setTimeZone(nextTimeZone: string | undefined) {
      timeZone = nextTimeZone;
    },
    setMessages(nextMessages: LuceneInputMessages | undefined) {
      messages = nextMessages;
      completionController.setMessages(nextMessages);
      notifyDiagnostics(view);
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

function toCodeMirrorDiagnostic(diagnostic: ComponentDiagnostic): CodeMirrorDiagnostic {
  return {
    from: diagnostic.from,
    to: diagnostic.to,
    severity: diagnostic.severity === 'error' ? 'error' : 'warning',
    message: diagnostic.message,
    markClass: getDiagnosticMarkClass(diagnostic)
  };
}

function getDiagnosticMarkClass(diagnostic: ComponentDiagnostic): string | undefined {
  if (diagnostic.code === 'unknownField') {
    return 'lucene-diagnostic-unknown-field';
  }

  if (diagnostic.code === 'missingToken' && diagnostic.params?.expected === 'field value') {
    return 'lucene-diagnostic-missing-value';
  }

  return undefined;
}
