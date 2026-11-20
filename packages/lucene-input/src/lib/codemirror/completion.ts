import type { EditorView } from '@codemirror/view';
import {
  evaluateDateMath,
  formatDateMathValue,
  fromZonedDateParts,
  getDatePartsInTimeZone
} from '../date-math';
import { FieldCompletionController } from '../field-completion';
import { localizeCompletionPreview, localizeFieldType, localizeSyntaxCompletion } from '../i18n';
import type { LuceneField, LuceneFieldType, LuceneInputMessages } from '../types';

export type LuceneCompletionOption = {
  label: string;
  apply: string;
  detail?: string;
  info?: string;
  kind: 'field' | 'syntax' | 'value';
  section: string;
};

export type LuceneCompletionResult = {
  from: number;
  to: number;
  query: string;
  options: LuceneCompletionOption[];
};

type SectionLabels = {
  fields: string;
  syntax: string;
  values: string;
};

type SyntaxCompletionKey = Parameters<typeof localizeSyntaxCompletion>[0];
type TypedValueCompletionTemplate = {
  label: string;
  labelCode?: SyntaxCompletionKey;
  apply: string;
  matchText?: string;
  info: SyntaxCompletionKey;
};
type TypedValueCompletionOption = {
  label: string;
  apply: string;
  matchText: string;
  info: SyntaxCompletionKey;
};

export async function getLuceneCompletions(
  view: EditorView,
  completionController: FieldCompletionController,
  sectionLabels: SectionLabels,
  locale: string,
  messages: LuceneInputMessages | undefined,
  fields: LuceneField[],
  timeZone?: string
): Promise<LuceneCompletionResult | null> {
  const cursor = view.state.selection.main;
  if (!cursor.empty || !view.hasFocus) {
    return null;
  }

  const value = view.state.doc.toString();
  const fieldValue = await completionController.completeValue(value, cursor.head);
  if (fieldValue) {
    return toLuceneCompletion(fieldValue, cursor.head, sectionLabels.values, 'value');
  }

  const typedOperator = getTypedFieldOperatorCompletions(value, cursor.head, fields, sectionLabels.syntax, locale, messages);
  if (typedOperator) {
    return typedOperator;
  }

  const typedValue = getTypedFieldValueCompletions(
    value,
    cursor.head,
    fields,
    sectionLabels.values,
    locale,
    messages,
    timeZone
  );
  if (typedValue) {
    return typedValue;
  }

  const beforeCursor = value.slice(0, cursor.head);
  if (/(?:^|[\s(])([A-Za-z_][\w.-]*)\s*:/.test(beforeCursor)) {
    return getLuceneSyntaxCompletions(value, cursor.head, sectionLabels.syntax, locale, messages);
  }

  const fieldName = completionController.completeFields(value, cursor.head);
  return combineLuceneCompletions(
    fieldName ? toLuceneCompletion(fieldName, cursor.head, sectionLabels.fields, 'field') : null,
    getLuceneSyntaxCompletions(value, cursor.head, sectionLabels.syntax, locale, messages)
  );
}


function combineLuceneCompletions(
  ...results: (LuceneCompletionResult | null)[]
): LuceneCompletionResult | null {
  const available = results.filter((result): result is LuceneCompletionResult => Boolean(result?.options.length));
  const first = available[0];
  if (!first) {
    return null;
  }

  return {
    from: Math.min(...available.map((result) => result.from)),
    to: Math.max(...available.map((result) => result.to)),
    query: first.query,
    options: available.flatMap((result) => result.options)
  };
}

function toLuceneCompletion(
  result: {
    from: number;
    options: { label: string; value: string; detail?: string; description?: string }[];
  },
  to: number,
  section: string,
  kind: LuceneCompletionOption['kind']
): LuceneCompletionResult {
  return {
    from: result.from,
    to,
    query: '',
    options: result.options.map((option) => ({
      label: option.label,
      apply: kind === 'field' ? `${option.value}:` : option.value,
      detail: option.detail,
      info: option.description,
      kind,
      section
    }))
  };
}

const luceneSyntaxCompletionOptions = [
  { label: 'AND', apply: 'AND ', detail: 'operator', info: 'andDescription' },
  { label: 'OR', apply: 'OR ', detail: 'operator', info: 'orDescription' },
  { label: 'NOT', apply: 'NOT ', detail: 'operator', info: 'notDescription' },
  { label: '(', apply: '(', detail: 'group', info: 'openGroupDescription' },
  { label: ')', apply: ')', detail: 'group', info: 'closeGroupDescription' }
] satisfies {
  label: string;
  apply: string;
  detail: SyntaxCompletionKey;
  info: SyntaxCompletionKey;
}[];

const typedValueCompletionOptions: Record<Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>, TypedValueCompletionTemplate[]> = {
  date: [
    { label: 'now/d', labelCode: 'todayLabel', apply: 'now/d', info: 'dateExampleDescription' },
    { label: 'now-1d/d', apply: 'now-1d/d', info: 'dateExampleDescription' },
    { label: 'now-7d/d', apply: 'now-7d/d', info: 'dateExampleDescription' },
    { label: 'now-30d/d', apply: 'now-30d/d', info: 'dateExampleDescription' },
    { label: '>=now-7d/d', apply: '>=now-7d/d', info: 'comparisonDescription' },
    { label: '<=now/d', apply: '<=now/d', info: 'comparisonDescription' },
    { label: '[now-7d/d TO now/d]', labelCode: 'last7DaysLabel', apply: '[now-7d/d TO now/d]', info: 'rangeDescription' },
    {
      label: '[now-30d/d TO now/d]',
      labelCode: 'last30DaysLabel',
      apply: '[now-30d/d TO now/d]',
      info: 'rangeDescription'
    },
    { label: '[* TO now/d]', apply: '[* TO now/d]', info: 'rangeDescription' },
    { label: '[now-7d/d TO *]', apply: '[now-7d/d TO *]', info: 'rangeDescription' }
  ],
  time: [
    { label: '14:30:00', apply: '14:30:00', info: 'timeExampleDescription' },
    { label: '>=14:30:00', apply: '>=14:30:00', info: 'comparisonDescription' },
    { label: '[09:00:00 TO 18:30:00]', apply: '[09:00:00 TO 18:30:00]', info: 'rangeDescription' }
  ],
  datetime: [
    { label: 'now', labelCode: 'nowLabel', apply: 'now', info: 'relativeTimeDescription' },
    { label: 'now-5m', apply: 'now-5m', info: 'relativeTimeDescription' },
    { label: 'now-10m', apply: 'now-10m', info: 'relativeTimeDescription' },
    { label: 'now-15m', apply: 'now-15m', info: 'relativeTimeDescription' },
    { label: 'now-30m', apply: 'now-30m', info: 'relativeTimeDescription' },
    { label: 'now-1h', apply: 'now-1h', info: 'relativeTimeDescription' },
    { label: 'now-24h', apply: 'now-24h', info: 'relativeTimeDescription' },
    { label: '>=now-5m', apply: '>=now-5m', info: 'comparisonDescription' },
    { label: '>=now-1h', apply: '>=now-1h', info: 'comparisonDescription' },
    { label: '<=now', apply: '<=now', info: 'comparisonDescription' },
    { label: '[now-5m TO now]', labelCode: 'last5MinutesLabel', apply: '[now-5m TO now]', info: 'rangeDescription' },
    { label: '[now-10m TO now]', labelCode: 'last10MinutesLabel', apply: '[now-10m TO now]', info: 'rangeDescription' },
    { label: '[now-15m TO now]', labelCode: 'last15MinutesLabel', apply: '[now-15m TO now]', info: 'rangeDescription' },
    { label: '[now-30m TO now]', labelCode: 'last30MinutesLabel', apply: '[now-30m TO now]', info: 'rangeDescription' },
    {
      label: '[now-1h TO now]',
      labelCode: 'lastHourLabel',
      apply: '[now-1h TO now]',
      info: 'rangeDescription'
    },
    {
      label: '[now-24h TO now]',
      labelCode: 'last24HoursLabel',
      apply: '[now-24h TO now]',
      info: 'rangeDescription'
    },
    { label: '[* TO now]', apply: '[* TO now]', info: 'rangeDescription' },
    { label: '[now-1h TO *]', apply: '[now-1h TO *]', info: 'rangeDescription' }
  ]
};

function getLuceneSyntaxCompletions(
  value: string,
  position: number,
  section: string,
  locale: string,
  messages: LuceneInputMessages | undefined
): LuceneCompletionResult | null {
  const token = readCompletionToken(value, position);
  if (!token?.text || token.text.includes(':')) {
    return null;
  }

  const query = token.text.toLowerCase();
  const options = luceneSyntaxCompletionOptions.filter((option) => {
    return option.label.toLowerCase().startsWith(query);
  });

  return options.length > 0
    ? {
        from: token.from,
        to: position,
        query: token.text,
        options: options.map((option) => ({
          label: option.label,
          apply: option.apply,
          detail: localizeSyntaxCompletion(option.detail, locale, messages),
          info: localizeSyntaxCompletion(option.info, locale, messages),
          kind: 'syntax',
          section
        }))
      }
    : null;
}

function getTypedFieldOperatorCompletions(
  value: string,
  position: number,
  fields: LuceneField[],
  section: string,
  locale: string,
  messages: LuceneInputMessages | undefined
): LuceneCompletionResult | null {
  const context = readTypedFieldOperatorContext(value, position, fields);
  if (!context) {
    return null;
  }

  const options: LuceneCompletionOption[] = [];

  if (isDateLikeFieldType(context.field.type) && 'to'.startsWith(context.query.toLowerCase())) {
    options.push({
      label: 'TO',
      apply: 'TO ',
      detail: localizeSyntaxCompletion('operator', locale, messages),
      info: localizeSyntaxCompletion('rangeDescription', locale, messages),
      kind: 'syntax',
      section
    });
  }

  return options.length > 0
    ? {
        from: context.from,
        to: position,
        query: context.query,
        options
      }
    : null;
}

function getTypedFieldValueCompletions(
  value: string,
  position: number,
  fields: LuceneField[],
  section: string,
  locale: string,
  messages: LuceneInputMessages | undefined,
  timeZone?: string
): LuceneCompletionResult | null {
  const context = readTypedFieldValueContext(value, position, fields);
  if (!context || !isDateLikeFieldType(context.field.type)) {
    return null;
  }

  if (!shouldShowTypedValueCompletions(context.query, context.fieldValue)) {
    return null;
  }

  const normalizedDateOptions = getNormalizedDateCompletions(
    context.query,
    context.field.type,
    context.quoted,
    timeZone
  );
  const baseOptions = getTypedValueCompletionOptions(context.field.type, locale, messages, timeZone).filter(
    (option) => shouldIncludeTypedValueCompletion(option, context.query)
  );
  const options = [...normalizedDateOptions, ...baseOptions].map((option) => ({
    label: option.label,
    apply: context.quote ? `${option.apply}${context.quote}` : option.apply,
    detail: localizeFieldType(context.field.type, locale, messages),
    info: getTypedValueCompletionInfo(option, context.quote, locale, messages),
    kind: 'value' as const,
    section
  }));

  return options.length > 0
    ? {
        from: context.from,
        to: position,
        query: context.query,
        options
      }
    : null;
}

function getTypedValueCompletionOptions(
  fieldType: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>,
  locale: string,
  messages: LuceneInputMessages | undefined,
  timeZone?: string
): TypedValueCompletionOption[] {
  if (fieldType === 'time') {
    return typedValueCompletionOptions.time.map(toTypedValueCompletionOption);
  }

  const referenceDate = new Date();
  return typedValueCompletionOptions[fieldType].map((option) => {
    const rawApply = option.apply;
    const localizedLabel = option.labelCode ? localizeSyntaxCompletion(option.labelCode, locale, messages) : option.label;
    return {
      label: formatDateMathCompletionLabel(localizedLabel, rawApply),
      apply: normalizeDateLikeApply(rawApply, fieldType, referenceDate, { timeZone }) ?? rawApply,
      matchText: option.matchText ?? rawApply,
      info: option.info
    };
  });
}

function toTypedValueCompletionOption(option: TypedValueCompletionTemplate): TypedValueCompletionOption {
  return {
    label: option.label,
    apply: option.apply,
    matchText: option.matchText ?? option.apply,
    info: option.info
  };
}

function getTypedValueCompletionInfo(
  option: { apply: string },
  closingQuote: string | null,
  locale: string,
  messages: LuceneInputMessages | undefined
): string {
  const apply = closingQuote ? `${option.apply}${closingQuote}` : option.apply;
  return localizeCompletionPreview(apply, locale, messages);
}

function formatDateMathCompletionLabel(label: string, apply: string): string {
  return label === apply ? label : `${label} · ${apply}`;
}

function shouldIncludeTypedValueCompletion(option: TypedValueCompletionOption, query: string): boolean {
  if ((query === '>' || query === '<') && option.matchText.startsWith(`${query}=`)) {
    return false;
  }

  const normalizedQuery = query.toLowerCase();
  return [option.apply, option.label, option.matchText].some((value) => value.toLowerCase().startsWith(normalizedQuery));
}

function getNormalizedDateCompletions(
  query: string,
  fieldType: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>,
  quoted: boolean,
  timeZone?: string
): TypedValueCompletionOption[] {
  if (fieldType === 'time') {
    return [];
  }

  const apply = normalizeDateLikeApply(query, fieldType, new Date(), {
    quoteDatetime: !quoted,
    timeZone
  });
  return apply && apply !== query ? [{ label: apply, apply, matchText: query, info: 'normalizedDateDescription' }] : [];
}

function normalizeDateLikeApply(
  value: string,
  fieldType: Extract<LuceneFieldType, 'date' | 'datetime'>,
  referenceDate: Date,
  options: { quoteDatetime?: boolean; timeZone?: string } = {}
): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  const comparison = /^(>=|<=|>|<)(.+)$/.exec(trimmed);
  if (comparison) {
    const valueApply = normalizeDateLikeApply(comparison[2].trim(), fieldType, referenceDate, options);
    return valueApply ? `${comparison[1]}${valueApply}` : null;
  }

  const range = /^\[\s*(.*?)\s+to\s+(.*?)\s*\]$/i.exec(trimmed);
  if (range) {
    const start = range[1] === '*' ? '*' : normalizeDateLikeApply(range[1], fieldType, referenceDate, options);
    const end = range[2] === '*' ? '*' : normalizeDateLikeApply(range[2], fieldType, referenceDate, options);
    return start && end ? `[${start} TO ${end}]` : null;
  }

  const partialDate = normalizePartialDate(trimmed, referenceDate, options.timeZone);
  if (partialDate) {
    return formatDateCompletion(partialDate, fieldType, options);
  }

  const dateMath = evaluateDateMath(trimmed, referenceDate, options.timeZone);
  return dateMath ? formatDateCompletion(dateMath, fieldType, options) : null;
}

function normalizePartialDate(query: string, referenceDate: Date, timeZone?: string): Date | null {
  const expandedQuery = expandCurrentYearPrefix(query, referenceDate, timeZone);
  if (expandedQuery) {
    return normalizePartialDate(expandedQuery, referenceDate, timeZone);
  }

  const match = /^(\d{4})(?:-(\d{1,2})(?:-(\d{1,2}))?)?$/.exec(query);
  if (!match) {
    return null;
  }

  const year = match[1];
  const month = match[2];
  const day = match[3];
  const today = getDatePartsInTimeZone(referenceDate, timeZone);
  const normalizedMonth = Number(month ?? today.month);
  const normalizedDay = Number(day ?? today.day);
  const maxDay = new Date(Date.UTC(Number(year), normalizedMonth, 0)).getUTCDate();
  if (normalizedMonth < 1 || normalizedMonth > 12 || normalizedDay < 1 || normalizedDay > maxDay) {
    return null;
  }

  return fromZonedDateParts(
    {
      year: Number(year),
      month: normalizedMonth,
      day: normalizedDay,
      weekday: 0,
      hour: 0,
      minute: 0,
      second: 0,
      millisecond: 0
    },
    timeZone
  );
}

function expandCurrentYearPrefix(query: string, referenceDate: Date, timeZone?: string): string | null {
  if (!/^\d{1,3}$/.test(query)) {
    return null;
  }

  const currentYear = String(getDatePartsInTimeZone(referenceDate, timeZone).year);
  return currentYear.startsWith(query) ? currentYear : null;
}

function formatDateCompletion(
  date: Date,
  fieldType: Extract<LuceneFieldType, 'date' | 'datetime'>,
  options: { quoteDatetime?: boolean; timeZone?: string } = {}
): string {
  return formatDateMathValue(date, fieldType, {
    quoteDatetime: options.quoteDatetime,
    timeZone: options.timeZone
  });
}

function shouldShowTypedValueCompletions(query: string, fieldValue: string): boolean {
  return query.length > 0 || fieldValue.trim().length === 0;
}

function readTypedFieldOperatorContext(
  value: string,
  position: number,
  fields: LuceneField[]
): { field: LuceneField & { type: LuceneFieldType }; query: string; from: number } | null {
  const beforeCursor = value.slice(0, position);
  const matches = [...beforeCursor.matchAll(/(?:^|[\s(])([A-Za-z_][\w.-]*)\s*:\s*/g)];
  const match = matches.at(-1);
  if (!match) {
    return null;
  }

  const field = fields.find((candidate): candidate is LuceneField & { type: LuceneFieldType } => {
    return candidate.name === match[1] && Boolean(candidate.type);
  });

  if (!field || !isComparableFieldType(field.type)) {
    return null;
  }

  const valueFrom = (match.index ?? 0) + match[0].length;
  const fieldValue = beforeCursor.slice(valueFrom);
  const token = /\S*$/.exec(fieldValue)?.[0] ?? '';
  const rangeQuery = /\b(t|to)$/i.exec(token)?.[1];
  if (rangeQuery && isDateLikeFieldType(field.type) && isInsideOpenRange(fieldValue)) {
    return {
      field,
      query: rangeQuery,
      from: position - rangeQuery.length
    };
  }

  return null;
}

function readTypedFieldValueContext(
  value: string,
  position: number,
  fields: LuceneField[]
): {
  field: LuceneField & { type: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'> };
  fieldValue: string;
  query: string;
  from: number;
  quoted: boolean;
  quote: string | null;
} | null {
  const beforeCursor = value.slice(0, position);
  const matches = [...beforeCursor.matchAll(/(?:^|[\s(])([A-Za-z_][\w.-]*)\s*:\s*/g)];
  const match = matches.at(-1);
  if (!match) {
    return null;
  }

  const field = fields.find(
    (candidate): candidate is LuceneField & { type: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'> } => {
      return candidate.name === match[1] && candidate.type !== undefined && isDateLikeFieldType(candidate.type);
    }
  );

  if (!field) {
    return null;
  }

  const valueFrom = (match.index ?? 0) + match[0].length;
  const fieldValue = beforeCursor.slice(valueFrom);
  const query = readTypedValueCompletionQuery(fieldValue, value.slice(position));
  if (!query) {
    return null;
  }

  return {
    field,
    fieldValue,
    query: query.text,
    from: valueFrom + query.from,
    quoted: query.quoted,
    quote: query.quote
  };
}

function readTypedValueCompletionQuery(
  fieldValue: string,
  afterCursor: string
): { text: string; from: number; quoted: boolean; quote: string | null } | null {
  if (fieldValue.length === 0) {
    return { text: '', from: 0, quoted: false, quote: null };
  }

  const quoted = readOpenQuotedCompletionQuery(fieldValue, afterCursor);
  if (quoted) {
    return quoted;
  }

  const token = /\S*$/.exec(fieldValue)?.[0] ?? '';
  if (token) {
    return isAtUnquotedTokenEnd(afterCursor)
      ? { text: token, from: fieldValue.length - token.length, quoted: false, quote: null }
      : null;
  }

  return fieldValue.trim().length === 0 ? { text: '', from: fieldValue.length, quoted: false, quote: null } : null;
}

function readOpenQuotedCompletionQuery(
  fieldValue: string,
  afterCursor: string
): { text: string; from: number; quoted: boolean; quote: string } | null {
  const quoteIndex = Math.max(fieldValue.lastIndexOf('"'), fieldValue.lastIndexOf("'"));
  if (quoteIndex === -1) {
    return null;
  }

  const quote = fieldValue[quoteIndex];
  const text = fieldValue.slice(quoteIndex + 1);
  if (hasUnescapedCharacter(text, quote) || hasUnescapedCharacter(afterCursor, quote)) {
    return null;
  }

  const beforeQuote = fieldValue.slice(0, quoteIndex);
  if (beforeQuote.trim().length > 0 && !/[\s[(<>]=?$/.test(beforeQuote)) {
    return null;
  }

  return {
    text,
    from: quoteIndex + 1,
    quoted: true,
    quote
  };
}

function isAtUnquotedTokenEnd(afterCursor: string): boolean {
  const next = afterCursor[0];
  return next === undefined || /[\s)\]]/.test(next);
}

function hasUnescapedCharacter(value: string, character: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === '\\') {
      index += 1;
      continue;
    }

    if (value[index] === character) {
      return true;
    }
  }

  return false;
}

function isInsideOpenRange(fieldValue: string): boolean {
  return fieldValue.lastIndexOf('[') > fieldValue.lastIndexOf(']');
}

function isComparableFieldType(type: LuceneFieldType): boolean {
  return type === 'number' || isDateLikeFieldType(type);
}

function isDateLikeFieldType(type: LuceneFieldType): boolean {
  return type === 'date' || type === 'time' || type === 'datetime';
}

function readCompletionToken(value: string, position: number): { text: string; from: number } | null {
  const beforeCursor = value.slice(0, position);
  const match = /(?:^|[\s(])([^\s()]*)$/.exec(beforeCursor);
  const text = match?.[1] ?? '';

  return {
    text,
    from: position - text.length
  };
}
