import { isDateMathValue } from './date-math';
import { localizeDiagnostics } from './i18n';
import { tokenizeLuceneQuery, type LuceneToken } from './syntax-highlighting';
import { buildLuceneSyntaxTree } from './syntax-tree';
import type {
  ComponentDiagnostic,
  LuceneDiagnosticsOptions,
  LuceneField,
  LuceneFieldType,
  LuceneInputMessages,
  LuceneSyntaxFeature,
  LuceneSyntaxTree
} from './types';

export function getLuceneDiagnostics(
  value: string,
  fields: LuceneField[] = [],
  locale = 'en',
  messages?: LuceneInputMessages,
  options: LuceneDiagnosticsOptions = {}
): ComponentDiagnostic[] {
  const tokens = tokenizeLuceneQuery(value);
  const tree = buildLuceneSyntaxTree(value, fields, tokens);
  const disabled = options.disabledSyntax ?? [];

  const diagnostics: ComponentDiagnostic[] = [
    ...getUnknownFieldDiagnostics(tokens, fields, options),
    ...getUnclosedLiteralDiagnostics(tokens, disabled),
    ...getTypedFieldValueDiagnostics(value, tree, fields),
    ...getGroupDiagnostics(tokens),
    ...getBooleanOperatorDiagnostics(tokens, value),
    ...getDisabledSyntaxDiagnostics(tokens, disabled)
  ];
  diagnostics.push(...getAstStructureDiagnostics(value, tree, diagnostics));
  diagnostics.push(...getUnparsedDiagnostics(tree, diagnostics));

  return localizeDiagnostics(diagnostics, locale, messages);
}

/** The syntax the host turned off, wherever it is written. */
function getDisabledSyntaxDiagnostics(
  tokens: readonly LuceneToken[],
  disabled: readonly LuceneSyntaxFeature[]
): ComponentDiagnostic[] {
  if (disabled.length === 0) {
    return [];
  }

  const diagnostics: ComponentDiagnostic[] = [];
  for (const token of tokens) {
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

function getUnclosedLiteralDiagnostics(
  tokens: readonly LuceneToken[],
  disabled: readonly LuceneSyntaxFeature[]
): ComponentDiagnostic[] {
  const diagnostics: ComponentDiagnostic[] = [];

  for (const token of tokens) {
    if (token.type === 'string' || (token.type === 'date' && (token.text[0] === '"' || token.text[0] === "'"))) {
      const delimiter = token.text[0];
      if (!isClosedDelimited(token.text, delimiter)) {
        diagnostics.push({
          code: 'missingToken',
          message: '',
          severity: 'error',
          from: token.from,
          to: token.to,
          params: { expected: 'closing quote', delimiter }
        });
      }
      continue;
    }

    if (token.type === 'regex' && !disabled.includes('regex') && !isClosedDelimited(token.text, '/')) {
      diagnostics.push({
        code: 'missingToken',
        message: '',
        severity: 'error',
        from: token.from,
        to: token.to,
        params: { expected: 'closing regex' }
      });
    }
  }

  return diagnostics;
}

function isClosedDelimited(text: string, delimiter: string): boolean {
  if (text.length < 2 || text[0] !== delimiter) {
    return false;
  }

  for (let index = 1; index < text.length; index += 1) {
    if (text[index] === '\\') {
      index += 1;
      continue;
    }

    if (text[index] === delimiter) {
      return index === text.length - 1;
    }
  }

  return false;
}

/**
 * Text the query grammar cannot place, such as a stray `)` or `:`, unless
 * another error already covers where it starts.
 */
function getUnparsedDiagnostics(tree: LuceneSyntaxTree, reported: ComponentDiagnostic[]): ComponentDiagnostic[] {
  const unparsed = tree.children?.find((child) => child.type === 'UnparsedTokens');
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

function getAstStructureDiagnostics(
  value: string,
  tree: LuceneSyntaxTree,
  reported: readonly ComponentDiagnostic[]
): ComponentDiagnostic[] {
  const diagnostics: ComponentDiagnostic[] = [];

  const visit = (node: LuceneSyntaxTree): void => {
    const children = node.children ?? [];

    switch (node.type) {
      case 'Node': {
        const [fieldNode, termNode] = children;
        if (fieldNode && termNode?.type === 'Missing' && termNode.from !== undefined) {
          const from = termNode.from;
          const to = extendTrailingWhitespace(value, from);
          if (!isSpanCovered(reported, from, to)) {
            diagnostics.push({
              code: 'missingToken',
              message: '',
              severity: 'error',
              from,
              to,
              params: { expected: 'field value', field: fieldNode.value ?? '' }
            });
          }
        }
        if (termNode) {
          visit(termNode);
        }
        return;
      }

      case 'GroupExpression': {
        const child = children[0];
        if (child?.type === 'Missing' && node.from !== undefined && node.to !== undefined) {
          diagnostics.push({
            code: 'missingToken',
            message: '',
            severity: 'error',
            from: node.from,
            to: node.to,
            params: { expected: 'group expression' }
          });
          return;
        }
        for (const item of children) {
          visit(item);
        }
        return;
      }

      case 'NotExpression':
      case 'FieldTermNotExpression':
      case 'RequiredExpression':
      case 'FieldTermRequiredExpression': {
        const child = children[0];
        if (child?.type === 'Missing' && node.from !== undefined && node.to !== undefined) {
          const to = extendTrailingWhitespace(value, node.to);
          if (!isSpanCovered(reported, node.from, to)) {
            diagnostics.push({
              code: 'missingToken',
              message: '',
              severity: 'error',
              from: node.from,
              to,
              params: { expected: 'term', operator: node.operator ?? '' }
            });
          }
          return;
        }
        for (const item of children) {
          visit(item);
        }
        return;
      }

      case 'FieldComparisonExpression': {
        const child = children[0];
        if (child?.type === 'Missing' && node.from !== undefined && node.to !== undefined) {
          const to = extendTrailingWhitespace(value, node.to);
          if (!isSpanCovered(reported, node.from, to)) {
            diagnostics.push({
              code: 'missingToken',
              message: '',
              severity: 'error',
              from: node.from,
              to,
              params: { expected: 'comparison value', operator: node.operator ?? '' }
            });
          }
          return;
        }
        for (const item of children) {
          visit(item);
        }
        return;
      }

      case 'FieldRangeExpression': {
        const [startNode, endNode] = children;
        if (startNode?.type === 'Missing' && startNode.from !== undefined && startNode.to !== undefined) {
          diagnostics.push({
            code: 'missingToken',
            message: '',
            severity: 'error',
            from: startNode.from,
            to: startNode.to,
            params: { expected: 'range start' }
          });
        }
        if (!node.operator && node.from !== undefined && node.to !== undefined) {
          diagnostics.push({
            code: 'missingToken',
            message: '',
            severity: 'error',
            from: startNode?.to ?? node.from,
            to: endNode?.from ?? node.to,
            params: { expected: 'TO' }
          });
        }
        if (endNode?.type === 'Missing' && endNode.from !== undefined && endNode.to !== undefined) {
          diagnostics.push({
            code: 'missingToken',
            message: '',
            severity: 'error',
            from: endNode.from,
            to: endNode.to,
            params: { expected: 'range end' }
          });
        }
        if (node.closed === false && node.from !== undefined) {
          diagnostics.push({
            code: 'missingToken',
            message: '',
            severity: 'error',
            from: node.from,
            to: node.from + 1,
            params: { expected: 'closing bracket', delimiter: node.inclusive?.[0] === false ? '}' : ']' }
          });
        }
        return;
      }

      case 'UnparsedTokens':
        return;

      default:
        for (const child of children) {
          visit(child);
        }
    }
  };

  visit(tree);
  return diagnostics;
}

function extendTrailingWhitespace(value: string, pos: number): number {
  let cursor = pos;
  while (cursor < value.length && /\s/.test(value[cursor])) {
    cursor += 1;
  }
  return cursor;
}

function isSpanCovered(reported: readonly ComponentDiagnostic[], from: number, to: number): boolean {
  return reported.some(
    (item) =>
      item.severity === 'error' &&
      ((item.from <= from && from < Math.max(item.to, item.from + 1)) ||
        (item.from >= from && item.from <= to))
  );
}

function getBooleanOperatorDiagnostics(tokens: readonly LuceneToken[], value: string): ComponentDiagnostic[] {
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

function nextMeaningfulToken(tokens: readonly LuceneToken[], current: LuceneToken): LuceneToken | undefined {
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
  tokens: readonly LuceneToken[],
  fields: LuceneField[],
  options: LuceneDiagnosticsOptions
): ComponentDiagnostic[] {
  if (fields.length === 0) {
    return [];
  }

  const knownFields = new Set(fields.map((field) => field.name));
  const diagnostics: ComponentDiagnostic[] = [];

  for (const token of tokens) {
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

type TypedField = {
  name: string;
  type: Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'>;
};

function getTypedFieldValueDiagnostics(
  value: string,
  tree: LuceneSyntaxTree,
  fields: LuceneField[]
): ComponentDiagnostic[] {
  const typedFields = new Map<string, TypedField>();
  for (const field of fields) {
    if (field.type && isTypedFieldType(field.type)) {
      typedFields.set(field.name, { name: field.name, type: field.type });
    }
  }
  if (typedFields.size === 0) {
    return [];
  }

  const diagnostics: ComponentDiagnostic[] = [];

  const visit = (node: LuceneSyntaxTree, activeField: TypedField | undefined): void => {
    const children = node.children ?? [];

    switch (node.type) {
      case 'Node': {
        const [fieldNode, termNode] = children;
        if (fieldNode && termNode) {
          visit(termNode, typedFields.get(fieldNode.value ?? ''));
        }
        return;
      }

      case 'FieldRangeExpression': {
        if (!activeField) {
          return;
        }
        for (const endpoint of children) {
          if (endpoint.type !== 'Missing') {
            visit(endpoint, activeField);
          }
        }
        return;
      }

      case 'FieldComparisonExpression': {
        if (!activeField) {
          return;
        }
        const child = children[0];
        if (child && child.type !== 'Missing') {
          visit(child, activeField);
        }
        return;
      }

      case 'DateTerm':
      case 'DateTimeTerm':
      case 'TimeTerm':
      case 'DateMathTerm':
      case 'SearchTerm':
      case 'WildcardTerm': {
        if (!activeField || node.from === undefined || node.to === undefined) {
          return;
        }
        const raw = value.slice(node.from, node.to);
        if (raw === '*') {
          return;
        }
        if ((raw[0] === '"' || raw[0] === "'") && !isClosedDelimited(raw, raw[0])) {
          return;
        }
        diagnostics.push(...validateSingleTypedValue(activeField.name, activeField.type, raw, node.from, node.to));
        return;
      }

      case 'UnparsedTokens':
        return;

      default:
        for (const child of children) {
          visit(child, activeField);
        }
    }
  };

  visit(tree, undefined);
  return diagnostics;
}

function isTypedFieldType(
  type: LuceneFieldType
): type is Extract<LuceneFieldType, 'number' | 'date' | 'time' | 'datetime'> {
  return type === 'number' || type === 'date' || type === 'time' || type === 'datetime';
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

function getGroupDiagnostics(tokens: readonly LuceneToken[]): ComponentDiagnostic[] {
  const stack: LuceneToken[] = [];

  for (const token of tokens) {
    if (token.type !== 'punctuation') {
      continue;
    }
    if (token.text === '(') {
      stack.push(token);
    } else if (token.text === ')') {
      stack.pop();
    }
  }

  const firstUnclosed = stack[0];
  if (!firstUnclosed) {
    return [];
  }

  return [
    {
      code: 'unclosedGroup',
      message: '',
      severity: 'error',
      from: firstUnclosed.from,
      to: firstUnclosed.to,
      params: {}
    }
  ];
}
