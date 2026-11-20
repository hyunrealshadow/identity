import { localizeFieldType } from './i18n';
import type { LuceneField, LuceneFieldValueOption } from './types';
import type { LuceneInputMessages } from './types';

export type CompletionOption = LuceneFieldValueOption;

export type CompletionResult = {
  from: number;
  options: CompletionOption[];
};

export type FieldValueContext = {
  fieldName: string;
  query: string;
  from: number;
  to: number;
};

export function getFieldNameCompletions(
  value: string,
  position: number,
  fields: LuceneField[],
  locale = 'en',
  messages?: LuceneInputMessages
): CompletionResult | null {
  const token = readCurrentToken(value, position);
  if (!token || token.text.includes(':')) {
    return null;
  }

  const options = fields
    .filter((field) => field.name.toLowerCase().startsWith(token.text.toLowerCase()))
    .map((field) => ({
      label: field.name,
      value: field.name,
      detail: field.type ? localizeFieldType(field.type, locale, messages) : undefined,
      description: field.description
    }));

  return options.length > 0 ? { from: token.from, options } : null;
}

export function getFieldValueContext(
  value: string,
  position: number,
  fields: LuceneField[]
): FieldValueContext | null {
  const beforeCursor = value.slice(0, position);
  const match = /(?:^|[\s(])([A-Za-z_][\w.-]*)\s*:\s*([^\s()]*)$/.exec(beforeCursor);
  if (!match?.[1]) {
    return null;
  }

  const fieldName = match[1];
  if (!fields.some((field) => field.name === fieldName)) {
    return null;
  }

  const query = match[2] ?? '';
  return {
    fieldName,
    query,
    from: position - query.length,
    to: position
  };
}

export class FieldCompletionController {
  #fields: LuceneField[];
  #locale: string;
  #messages: LuceneInputMessages | undefined;
  #currentSearch: AbortController | undefined;

  constructor(fields: LuceneField[] = [], locale = 'en', messages?: LuceneInputMessages) {
    this.#fields = fields;
    this.#locale = locale;
    this.#messages = messages;
  }

  setFields(fields: LuceneField[]): void {
    this.#fields = fields;
  }

  setLocale(locale: string): void {
    this.#locale = locale;
  }

  setMessages(messages: LuceneInputMessages | undefined): void {
    this.#messages = messages;
  }

  completeFields(value: string, position: number): CompletionResult | null {
    return getFieldNameCompletions(value, position, this.#fields, this.#locale, this.#messages);
  }

  async completeValue(value: string, position: number): Promise<CompletionResult | null> {
    const context = getFieldValueContext(value, position, this.#fields);
    if (!context) {
      return null;
    }

    const field = this.#fields.find((candidate) => candidate.name === context.fieldName);
    if (!field?.search) {
      return null;
    }

    this.#currentSearch?.abort();
    const abortController = new AbortController();
    this.#currentSearch = abortController;

    const options = await field.search(context.query, {
      field,
      value,
      position,
      signal: abortController.signal
    });

    if (abortController.signal.aborted || this.#currentSearch !== abortController) {
      return null;
    }

    return {
      from: context.from,
      options
    };
  }
}

function readCurrentToken(value: string, position: number): { text: string; from: number } | null {
  const beforeCursor = value.slice(0, position);
  const match = /(?:^|[\s(])([^\s()]*)$/.exec(beforeCursor);
  const text = match?.[1] ?? '';
  if (!text) {
    return null;
  }

  return {
    text,
    from: position - text.length
  };
}
