import { localizeDiagnostics } from './i18n';
import { isDateMathValue } from './date-math';
import { tokenizeLuceneQuery, type LuceneToken } from './syntax-highlighting';
import { buildLuceneSyntaxTree } from './syntax-tree';
import type {
  ComponentDiagnostic,
  LuceneDiagnosticsOptions,
  LuceneField,
  LuceneFieldType,
  LuceneInputMessages,
  LuceneSyntaxFeature
} from './types';

export function getLuceneDiagnostics(
  value: string,
  fields: LuceneField[] = [],
  locale = 'en',
  messages?: LuceneInputMessages,
  options: LuceneDiagnosticsOptions = {}
): ComponentDiagnostic[] {
  const diagnostics: ComponentDiagnostic[] = [
    ...getUnknownFieldDiagnostics(value, fields, options),
    ...getTypedFieldValueDiagnostics(value, fields),
    ...getGroupDiagnostics(value),
    ...getMissingValueDiagnostics(value),
    ...getBooleanOperatorDiagnostics(value),
    ...getDisabledSyntaxDiagnostics(value, options.disabledSyntax ?? [])
  ];
  diagnostics.push(...getUnparsedDiagnostics(value, diagnostics));

  return localizeDiagnostics(diagnostics, locale, messages);
}

/** The syntax the host turned off, wherever it is written. */
function getDisabledSyntaxDiagnostics(
  value: string,
  disabled: readonly LuceneSyntaxFeature[]
): ComponentDiagnostic[] {
  if (disabled.length === 0) {
    return [];
  }

  const diagnostics: ComponentDiagnostic[] = [];
  for (const token of tokenizeLuceneQuery(value)) {
    const feature = syntaxFeature(token);
    if (feature && disabled.includes(feature)) {
      diagnostics.push({
        code: 'unsupportedSyntax',
        message: '',
        severity: 'error',
        from: token.from,
        to: token.to,
        params: { feature, token: token.text }
      });
    }
  }
  return diagnostics;
}

function syntaxFeature(token: LuceneToken): LuceneSyntaxFeature | null {
  if (token.type === 'regex') return 'regex';
  if (token.type === 'punctuation' && (token.text === '{' || token.text === '}')) return 'exclusiveRanges';
  if (token.type !== 'operator') return null;
  if (token.text === '+' || token.text === '-') return 'prefixOperators';
  if (token.text.startsWith('~')) return 'fuzzy';
  if (token.text.startsWith('^')) return 'boost';
  return null;
}

/**
 * Text the query grammar cannot place, such as a stray `)` or `:`, unless
 * another error already covers where it starts.
 */
function getUnparsedDiagnostics(value: string, reported: ComponentDiagnostic[]): ComponentDiagnostic[] {
  const unparsed = buildLuceneSyntaxTree(value).children?.find((child) => child.type === 'UnparsedTokens');
  const first = unparsed?.children?.[0];
  if (!first || first.from === undefined || first.to === undefined) {
    return [];
  }

  const from = first.from;
  const covered = reported.some(
    (item) => item.severity === 'error' && item.from <= from && from < Math.max(item.to, item.from + 1)
  );
  return covered
    ? []
    : [
        {
          code: 'unexpectedToken',
          message: '',
          severity: 'error',
          from,
          to: first.to,
          params: { token: first.value ?? '' }
        }
      ];
}

function getBooleanOperatorDiagnostics(value: string): ComponentDiagnostic[] {
  const tokens = tokenizeLuceneQuery(value);
  let previousMeaningful: LuceneToken | undefined;

  for (const token of tokens) {
    if (!isBooleanOperator(token)) {
      previousMeaningful = token;
      continue;
    }

    if (isUnaryOperator(token)) {
      previousMeaningful = token;
      continue;
    }

    if (!previousMeaningful || !canEndExpression(previousMeaningful)) {
      return [unexpectedToken(token)];
    }

    const next = nextMeaningfulToken(tokens, token);
    if (!next) {
      return [
        {
          code: 'missingToken',
          message: '',
          severity: 'error',
          from: token.from,
          to: value.length,
          params: { expected: 'term', operator: token.text }
        }
      ];
    }

    if (isBooleanOperator(next) && !isUnaryOperator(next)) {
      return [unexpectedToken(next)];
    }

    previousMeaningful = token;
  }

  return [];
}

function isBooleanOperator(token: LuceneToken): boolean {
  return token.type === 'operator' && /^(AND|OR|NOT|&&|\|\||!)$/i.test(token.text);
}

function isUnaryOperator(token: LuceneToken): boolean {
  return /^(!|NOT|-|\+)$/i.test(token.text);
}

function canEndExpression(token: LuceneToken): boolean {
  return (
    // A closed group or range: `(a) AND b`, `field:[x TO y] AND b`.
    (token.type === 'punctuation' && /^[)\]}]$/.test(token.text)) ||
    // A fuzzy or boost suffix: `a~2 AND b`.
    (token.type === 'operator' && /^[~^]/.test(token.text)) ||
    token.type === 'term' ||
    token.type === 'date' ||
    token.type === 'string' ||
    token.type === 'regex' ||
    token.type === 'wildcard'
  );
}

function nextMeaningfulToken(tokens: LuceneToken[], current: LuceneToken): LuceneToken | undefined {
  return tokens.find((token) => token.from >= current.to && token !== current);
}

function unexpectedToken(token: LuceneToken): ComponentDiagnostic {
  return {
    code: 'unexpectedToken',
    message: '',
    severity: 'error',
    from: token.from,
    to: token.to,
    params: { token: token.text }
  };
}

function getUnknownFieldDiagnostics(
  value: string,
  fields: LuceneField[],
  options: LuceneDiagnosticsOptions
): ComponentDiagnostic[] {
  if (fields.length === 0) {
    return [];
  }

  const knownFields = new Set(fields.map((field) => field.name));
  const diagnostics: ComponentDiagnostic[] = [];

  for (const token of tokenizeLuceneQuery(value)) {
    if (token.type !== 'field' || knownFields.has(token.text)) {
      continue;
    }

    diagnostics.push({
      code: 'unknownField',
      message: '',
      severity: options.disallowUnknownFields ? 'error' : 'warning',
      from: token.from,
      to: token.to,
      params: { field: token.text }
    });
  }

  return diagnostics;
}

function getTypedFieldValueDiagnostics(value: string, fields: LuceneField[]): ComponentDiagnostic[] {
  const typedFields = new Map(fields.filter((field) => field.type).map((field) => [field.name, field]));
  if (typedFields.size === 0) {
    return [];
  }

  const diagnostics: ComponentDiagnostic[] = [];
  const tokens = tokenizeLuceneQuery(value);
  const fieldStarts: { fieldName: string; valueFrom: number; from: number }[] = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== 'field' || tokens[index + 1]?.type !== 'fieldSeparator') {
      continue;
    }

    let valueFrom = tokens[index + 1].to;
    while (valueFrom < value.length && /\s/.test(value[valueFrom])) {
      valueFrom += 1;
    }
    fieldStarts.push({ fieldName: token.text, valueFrom, from: token.from });
  }

  for (let index = 0; index < fieldStarts.length; index += 1) {
    const entry = fieldStarts[index];
    const field = typedFields.get(entry.fieldName);
    if (!field?.type) {
      continue;
    }

    const nextFieldStart = fieldStarts[index + 1]?.from;
    const rawValue = fieldValueText(value.slice(entry.valueFrom, nextFieldStart)).trimEnd();
    if (!rawValue.trim()) {
      continue;
    }

    diagnostics.push(...validateTypedFieldValue(field.name, field.type, rawValue, entry.valueFrom));
  }

  return diagnostics;
}

function validateTypedFieldValue(
  field: string,
  type: LuceneFieldType,
  rawValue: string,
  valueFrom: number
): ComponentDiagnostic[] {
  if (type === 'number') {
    return validateComparableValue(field, 'number', rawValue, valueFrom);
  }

  if (isDateLikeFieldType(type)) {
    return validateDateLikeValue(field, type, rawValue, valueFrom);
  }

  return [];
}

function validateDateLikeValue(
  field: string,
  type: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>,
  rawValue: string,
  valueFrom: number
): ComponentDiagnostic[] {
  const range = readToRange(rawValue, valueFrom, type);
  if (range) {
    return [
      ...validateRangeEndpoint(field, type, range.start.value, range.start.from, range.start.to),
      ...validateRangeEndpoint(field, type, range.end.value, range.end.from, range.end.to)
    ];
  }

  return validateComparableValue(field, type, rawValue, valueFrom);
}

function validateRangeEndpoint(
  field: string,
  type: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>,
  rawValue: string,
  from: number,
  to: number
): ComponentDiagnostic[] {
  return rawValue === '*' ? [] : validateSingleTypedValue(field, type, rawValue, from, to);
}

function validateComparableValue(
  field: string,
  type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>,
  rawValue: string,
  valueFrom: number
): ComponentDiagnostic[] {
  const comparison = /^(>=|<=|>|<)\s*/.exec(rawValue);
  const offset = comparison?.[0].length ?? 0;
  const value = readCandidateValue(rawValue.slice(offset), valueFrom + offset);
  if (!value) {
    return [];
  }

  return validateSingleTypedValue(field, type, value.value, value.from, value.to);
}

function validateSingleTypedValue(
  field: string,
  type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>,
  rawValue: string,
  from: number,
  to: number
): ComponentDiagnostic[] {
  const quotedOrEscapedWhitespace = isQuoted(rawValue) || hasEscapedWhitespace(rawValue);
  const value = normalizeValue(rawValue);
  const valid = isValidTypedValue(type, value, quotedOrEscapedWhitespace);
  const repairable = !valid && isRepairableTypedValue(type, value);
  const params: ComponentDiagnostic['params'] = { field, expected: type };
  if (repairable) {
    params.repairable = true;
  }

  return valid
    ? []
    : [
        {
          code: 'invalidFieldValue',
          message: '',
          severity: repairable ? 'warning' : 'error',
          from,
          to,
          params
        }
      ];
}

function isValidTypedValue(
  type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>,
  value: string,
  allowLocalDatetimeSeparator: boolean
): boolean {
  switch (type) {
    case 'number':
      return isNumberValue(value);
    case 'date':
      return isDateValue(value);
    case 'time':
      return isTimeValue(value);
    case 'datetime':
      return isDatetimeValue(value, allowLocalDatetimeSeparator);
  }
}

function isRepairableTypedValue(
  type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>,
  value: string
): boolean {
  if (type !== 'date' && type !== 'datetime') {
    return false;
  }

  const dateLikeValue = stripOpenQuote(value);
  return isPartialDateValue(dateLikeValue);
}

function stripOpenQuote(value: string): string {
  return value[0] === '"' || value[0] === "'" ? value.slice(1) : value;
}

function isPartialDateValue(value: string): boolean {
  const match = /^(\d{1,4})(?:-(\d{1,2})(?:-(\d{1,2}))?)?$/.exec(value);
  if (!match) {
    return false;
  }

  const year = match[1];
  if (year.length < 4) {
    return String(new Date().getFullYear()).startsWith(year);
  }

  const month = match[2] === undefined ? 1 : Number(match[2]);
  const day = match[3] === undefined ? 1 : Number(match[3]);
  const maxDay = new Date(Number(year), month, 0).getDate();
  return month >= 1 && month <= 12 && day >= 1 && day <= maxDay;
}

/**
 * The text of one field value. A range ends at its closing bracket, so the
 * clauses that follow it (`field:[x TO y] AND other`) are not read as part of
 * the range.
 */
function fieldValueText(rawValue: string): string {
  if (rawValue[0] !== '[' && rawValue[0] !== '{') {
    return rawValue;
  }
  let quote: string | undefined;
  for (let index = 1; index < rawValue.length; index += 1) {
    const char = rawValue[index];
    if (char === '\\') {
      index += 1;
    } else if (quote) {
      if (char === quote) quote = undefined;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === ']' || char === '}') {
      return rawValue.slice(0, index + 1);
    }
  }
  return rawValue;
}

function readToRange(
  rawValue: string,
  valueFrom: number,
  type: Extract<LuceneFieldType, 'date' | 'time' | 'datetime'>
): { start: { value: string; from: number; to: number }; end: { value: string; from: number; to: number } } | null {
  const valuePattern = getValuePattern(type);
  const endpointPattern = `(?:${valuePattern}|${getQuotedValuePattern()}|\\*)`;
  const match = new RegExp(`^[\\[{]\\s*(${endpointPattern})\\s+to\\s+(${endpointPattern})\\s*[\\]}]$`, 'i').exec(
    rawValue
  );
  if (!match) {
    return null;
  }

  const startOffset = match[0].indexOf(match[1]);
  const endOffset = match[0].lastIndexOf(match[2]);
  return {
    start: {
      value: match[1],
      from: valueFrom + startOffset,
      to: valueFrom + startOffset + match[1].length
    },
    end: {
      value: match[2],
      from: valueFrom + endOffset,
      to: valueFrom + endOffset + match[2].length
    }
  };
}

function readCandidateValue(rawValue: string, from: number): { value: string; from: number; to: number } | null {
  const quoted = readQuotedCandidate(rawValue, from);
  if (quoted) {
    return quoted;
  }

  const candidate = readUnquotedCandidate(rawValue);
  if (!candidate) {
    return null;
  }

  const start = from + candidate.index;
  return {
    value: candidate.value,
    from: start,
    to: start + candidate.value.length
  };
}

function isDateLikeFieldType(type: LuceneFieldType): type is Extract<LuceneFieldType, 'date' | 'time' | 'datetime'> {
  return type === 'date' || type === 'time' || type === 'datetime';
}

function getValuePattern(type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>): string {
  if (type === 'number') {
    return '-?(?:\\d+|\\d*\\.\\d+)';
  }

  if (type === 'date') {
    return `(?:\\d{4}-\\d{2}-\\d{2}|${getDateMathPattern()})`;
  }

  if (type === 'time') {
    return '\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?';
  }

  return `(?:\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?(?:Z|[+-]\\d{2}:?\\d{2})|${getDateMathPattern()})`;
}

function getDateMathPattern(): string {
  return 'now(?:[+-]\\d+(?:ms|s|m|h|d|w|M|y))?(?:\\/(?:s|m|h|d|w|M|y))?';
}

function getQuotedValuePattern(): string {
  return `(?:"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')`;
}

function readQuotedCandidate(rawValue: string, from: number): { value: string; from: number; to: number } | null {
  const quote = rawValue[0];
  if (quote !== '"' && quote !== "'") {
    return null;
  }

  for (let index = 1; index < rawValue.length; index += 1) {
    if (rawValue[index] === '\\') {
      index += 1;
      continue;
    }

    if (rawValue[index] === quote) {
      return {
        value: rawValue.slice(0, index + 1),
        from,
        to: from + index + 1
      };
    }
  }

  return {
    value: rawValue,
    from,
    to: from + rawValue.length
  };
}

function readUnquotedCandidate(rawValue: string): { value: string; index: number } | null {
  let index = 0;
  while (index < rawValue.length && /\s/.test(rawValue[index])) {
    index += 1;
  }

  if (index >= rawValue.length) {
    return null;
  }

  let to = index;
  while (to < rawValue.length) {
    if (rawValue[to] === '\\') {
      to += 2;
      continue;
    }

    if (/\s/.test(rawValue[to])) {
      break;
    }

    to += 1;
  }

  return { value: rawValue.slice(index, to), index };
}

function isQuoted(value: string): boolean {
  return /^(['"]).*\1$/.test(value);
}

function normalizeValue(value: string): string {
  const unquoted = isQuoted(value) ? value.slice(1, -1) : value;
  return unquoted.replace(/\\(.)/g, '$1');
}

function hasEscapedWhitespace(value: string): boolean {
  return /\\\s/.test(value);
}

function isNumberValue(value: string): boolean {
  return /^-?(?:\d+|\d*\.\d+)$/.test(value);
}

function isDateValue(value: string): boolean {
  if (isDateMathValue(value)) {
    return true;
  }

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) {
    return false;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function isTimeValue(value: string): boolean {
  const match = /^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?$/.exec(value);
  if (!match) {
    return false;
  }

  const hour = Number(match[1]);
  const minute = Number(match[2]);
  const second = Number(match[3]);
  return hour <= 23 && minute <= 59 && second <= 59;
}

function isDatetimeValue(value: string, quoted: boolean): boolean {
  if (isDateMathValue(value)) {
    return true;
  }

  if (value.includes(' ') && !quoted) {
    return false;
  }

  const isoMatch = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)(Z|[+-]\d{2}:?\d{2})$/.exec(value);
  if (isoMatch) {
    return isDateValue(isoMatch[1]) && isTimeValue(isoMatch[2]);
  }

  const localMatch = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)$/.exec(value);
  return Boolean(localMatch && isDateValue(localMatch[1]) && isTimeValue(localMatch[2]));
}

function getGroupDiagnostics(value: string): ComponentDiagnostic[] {
  const stack: number[] = [];

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === '(') {
      stack.push(index);
    } else if (char === ')') {
      stack.pop();
    }
  }

  const firstUnclosed = stack[0];
  if (firstUnclosed === undefined) {
    return [];
  }

  return [
    {
      code: 'unclosedGroup',
      message: '',
      severity: 'error',
      from: firstUnclosed,
      to: firstUnclosed + 1,
      params: {}
    }
  ];
}

function getMissingValueDiagnostics(value: string): ComponentDiagnostic[] {
  const match = /(^|[\s(])([A-Za-z_][\w.-]*)\s*:\s*$/.exec(value);
  if (!match) {
    return [];
  }

  const from = (match.index ?? 0) + match[0].lastIndexOf(':') + 1;

  return [
    {
      code: 'missingToken',
      message: '',
      severity: 'error',
      from,
      to: value.length,
      params: { expected: 'field value', field: match[2] }
    }
  ];
}
