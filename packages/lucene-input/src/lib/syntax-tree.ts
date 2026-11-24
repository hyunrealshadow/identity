import { evaluateDateMath, formatDateMathValue, isDateMathValue } from './date-math';
import { tokenizeLuceneQuery, type LuceneToken } from './syntax-highlighting';
import type { LuceneField, LuceneFieldType, LuceneSyntaxTree } from './types';

export function buildLuceneSyntaxTree(value: string, fields: LuceneField[] = []): LuceneSyntaxTree {
  const parser = new SyntaxTreeParser(tokenizeLuceneQuery(value), fields);
  return parser.parse();
}

class SyntaxTreeParser {
  #cursor = 0;
  private readonly tokens: LuceneToken[];
  private readonly fieldTypes: Map<string, LuceneFieldType>;

  constructor(tokens: LuceneToken[], fields: LuceneField[]) {
    this.tokens = tokens;
    this.fieldTypes = new Map(
      fields.flatMap((field) => (field.type ? [[field.name, field.type] as const] : []))
    );
  }

  parse(): LuceneSyntaxTree {
    const expression = this.parseDefaultExpression();
    const children: LuceneSyntaxTree[] = expression ? [expression] : [];
    const rest = this.tokens.slice(this.#cursor);

    if (rest.length > 0) {
      children.push({
        type: 'UnparsedTokens',
        children: rest.map((token) => this.tokenNode(token))
      });
    }

    return { type: 'Query', children };
  }

  private parseDefaultExpression(): LuceneSyntaxTree | undefined {
    let left = this.parseOrExpression();
    if (!left) {
      return undefined;
    }

    while (this.startsPrimary(this.peek())) {
      const right = this.parseOrExpression();
      if (!right) {
        break;
      }

      left = this.binaryNode('IMPLICIT', left, right);
    }

    return left;
  }

  private parseOrExpression(): LuceneSyntaxTree | undefined {
    let left = this.parseAndExpression();
    if (!left) {
      return undefined;
    }

    while (this.matchOperator('OR')) {
      const operator = this.previous();
      const right = this.parseAndExpression();
      left = this.binaryNode(operator.text, left, right ?? this.missingNode(operator.to));
    }

    return left;
  }

  private parseAndExpression(): LuceneSyntaxTree | undefined {
    let left = this.parsePrimaryExpression();
    if (!left) {
      return undefined;
    }

    while (this.matchOperator('AND')) {
      const operator = this.previous();
      const right = this.parsePrimaryExpression();
      left = this.binaryNode(operator.text, left, right ?? this.missingNode(operator.to));
    }

    return left;
  }

  private parsePrimaryExpression(): LuceneSyntaxTree | undefined {
    const token = this.peek();
    if (!token) {
      return undefined;
    }

    if (this.isUnaryOperator(token)) {
      this.advance();
      return {
        type: token.text === '+' ? 'RequiredExpression' : 'NotExpression',
        operator: token.text,
        from: token.from,
        to: token.to,
        children: [this.parsePrimaryExpression() ?? this.missingNode(token.to)]
      };
    }

    if (token.type === 'punctuation' && token.text === '(') {
      return this.withModifiers(this.parseGroupExpression());
    }

    if (token.type === 'field' && this.peek(1)?.text === ':') {
      return this.parseFieldNode();
    }

    if (this.isTerm(token)) {
      return this.withModifiers(this.termNode(this.advanceTerm()));
    }

    return undefined;
  }

  private parseGroupExpression(): LuceneSyntaxTree {
    const open = this.advance();
    const expression = this.parseDefaultExpression() ?? this.missingNode(open.to);
    const close = this.peek()?.text === ')' ? this.advance() : undefined;

    return {
      type: 'GroupExpression',
      from: open.from,
      to: close?.to ?? expression.to,
      children: [expression]
    };
  }

  private parseFieldNode(): LuceneSyntaxTree {
    const field = this.advance();
    const colon = this.advance();
    const fieldType = this.fieldTypes.get(field.text);
    const term = this.parseFieldTerm(fieldType) ?? this.missingNode(colon.to);

    return {
      type: 'Node',
      from: field.from,
      to: term.to,
      children: [
        { type: 'Field', value: field.text, from: field.from, to: field.to },
        term
      ]
    };
  }

  private parseFieldTerm(fieldType: LuceneFieldType | undefined): LuceneSyntaxTree | undefined {
    const token = this.peek();
    if (!token) {
      return undefined;
    }

    if (this.isUnaryOperator(token)) {
      this.advance();
      return {
        type: token.text === '+' ? 'FieldTermRequiredExpression' : 'FieldTermNotExpression',
        operator: token.text,
        from: token.from,
        to: token.to,
        children: [this.parseFieldTerm(fieldType) ?? this.missingNode(token.to)]
      };
    }

    if (token.type === 'punctuation' && token.text === '(') {
      return this.withModifiers(this.parseGroupExpression());
    }

    if (this.isComparisonOperator(token)) {
      return this.parseFieldComparisonExpression(fieldType);
    }

    if (token.type === 'punctuation' && (token.text === '[' || token.text === '{')) {
      return this.parseFieldRangeExpression(fieldType);
    }

    if (this.isTerm(token)) {
      return this.withModifiers(this.termNode(this.advanceTerm(), fieldType));
    }

    return undefined;
  }

  private parseFieldRangeExpression(fieldType: LuceneFieldType | undefined): LuceneSyntaxTree {
    const open = this.advance();
    const startToken = this.peek();
    const start =
      startToken && this.isTerm(startToken) ? this.termNode(this.advanceTerm(), fieldType) : this.missingNode(open.to);
    const operator = this.peek();
    if (operator && /^to$/i.test(operator.text)) {
      this.advance();
    }

    const endToken = this.peek();
    const end =
      endToken && this.isTerm(endToken)
        ? this.termNode(this.advanceTerm(), fieldType)
        : this.missingNode(operator?.to ?? start.to ?? open.to);
    const closeText = this.peek()?.text;
    const close = closeText === ']' || closeText === '}' ? this.advance() : undefined;

    return {
      type: 'FieldRangeExpression',
      operator: operator?.text,
      from: open.from,
      to: close?.to ?? end.to,
      inclusive: [open.text === '[', close?.text !== '}'],
      children: [start, end]
    };
  }

  private startsPrimary(token: LuceneToken | undefined): boolean {
    return Boolean(
      token &&
        (this.isUnaryOperator(token) ||
          this.isTerm(token) ||
          (token.type === 'field' && this.peek(1)?.text === ':') ||
          (token.type === 'punctuation' && token.text === '('))
    );
  }

  private isTerm(token: LuceneToken): boolean {
    return (
      token.type === 'term' ||
      token.type === 'date' ||
      token.type === 'string' ||
      token.type === 'regex' ||
      token.type === 'wildcard'
    );
  }

  private isUnaryOperator(token: LuceneToken): boolean {
    return token.type === 'operator' && /^(!|NOT|-|\+)$/i.test(token.text);
  }

  /** Fuzzy (`~`, `~2`) and boost (`^2`) suffixes written right after a term or group. */
  private withModifiers(node: LuceneSyntaxTree): LuceneSyntaxTree {
    let result = node;
    for (
      let next = this.peek();
      next && next.type === 'operator' && next.from === result.to && /^[~^]/.test(next.text);
      next = this.peek()
    ) {
      this.advance();
      result = {
        type: next.text.startsWith('~') ? 'FuzzyExpression' : 'BoostExpression',
        operator: next.text,
        from: result.from,
        to: next.to,
        children: [result]
      };
    }
    return result;
  }

  private isComparisonOperator(token: LuceneToken): boolean {
    return token.type === 'operator' && /^(>=|<=|>|<)$/.test(token.text);
  }

  private parseFieldComparisonExpression(fieldType: LuceneFieldType | undefined): LuceneSyntaxTree {
    const operator = this.advance();
    const term = this.parseFieldTerm(fieldType) ?? this.missingNode(operator.to);

    return {
      type: 'FieldComparisonExpression',
      operator: operator.text,
      from: operator.from,
      to: term.to,
      children: [term]
    };
  }

  private matchOperator(kind: 'AND' | 'OR'): boolean {
    const token = this.peek();
    if (!token || token.type !== 'operator') {
      return false;
    }

    const matches = kind === 'AND' ? /^(AND|&&)$/i.test(token.text) : /^(OR|\|\|)$/i.test(token.text);
    if (matches) {
      this.advance();
    }

    return matches;
  }

  private binaryNode(operator: string, left: LuceneSyntaxTree, right: LuceneSyntaxTree): LuceneSyntaxTree {
    return {
      type: 'BinaryExpression',
      operator,
      from: left.from,
      to: right.to,
      children: [left, right]
    };
  }

  private termNode(token: LuceneToken, fieldType?: LuceneFieldType): LuceneSyntaxTree {
    const dateMath = evaluateDateMath(token.text);
    if (dateMath && fieldType === 'date') {
      return {
        type: 'DateTerm',
        value: formatDateMathValue(dateMath, 'date'),
        from: token.from,
        to: token.to
      };
    }

    if (dateMath && fieldType === 'datetime') {
      return {
        type: 'DateTimeTerm',
        value: formatDateMathValue(dateMath, 'datetime', { quoteDatetime: false }),
        from: token.from,
        to: token.to
      };
    }

    if (isDateMathValue(token.text)) {
      return {
        type: 'DateMathTerm',
        value: token.text,
        from: token.from,
        to: token.to
      };
    }

    if (fieldType === 'date') {
      const dateValue = readDateValue(token.text);
      if (dateValue) {
        return {
          type: 'DateTerm',
          value: dateValue,
          from: token.from,
          to: token.to
        };
      }
    }

    const normalizedValue =
      token.type === 'string' || token.type === 'date' || token.type === 'term'
        ? normalizeTermValue(token.text)
        : token.text;
    if (fieldType === 'datetime' && isLocalDateTimeValue(normalizedValue)) {
      return {
        type: 'DateTimeTerm',
        value: normalizedValue,
        from: token.from,
        to: token.to
      };
    }

    const dateLikeTermType = getDateLikeTermType(normalizedValue);
    if (dateLikeTermType) {
      return {
        type: dateLikeTermType,
        value: normalizedValue,
        from: token.from,
        to: token.to
      };
    }

    return {
      type: token.type === 'regex' ? 'RegexTerm' : token.type === 'wildcard' ? 'WildcardTerm' : 'SearchTerm',
      value: normalizedValue,
      from: token.from,
      to: token.to
    };
  }

  private tokenNode(token: LuceneToken): LuceneSyntaxTree {
    return {
      type: 'Token',
      value: token.text,
      from: token.from,
      to: token.to
    };
  }

  private missingNode(position: number): LuceneSyntaxTree {
    return {
      type: 'Missing',
      from: position,
      to: position
    };
  }

  private peek(offset = 0): LuceneToken | undefined {
    return this.tokens[this.#cursor + offset];
  }

  private previous(): LuceneToken {
    return this.tokens[this.#cursor - 1];
  }

  /**
   * One term, joining the pieces written without a gap between them, so
   * `user_*` is a single wildcard term rather than `user_` followed by `*`.
   */
  private advanceTerm(): LuceneToken {
    let token = this.advance();
    for (let next = this.peek(); next && next.from === token.to && this.joinsTerm(token, next); next = this.peek()) {
      this.advance();
      token = {
        type: token.type === 'wildcard' || next.type === 'wildcard' ? 'wildcard' : token.type,
        from: token.from,
        to: next.to,
        text: token.text + next.text
      };
    }
    return token;
  }

  private joinsTerm(token: LuceneToken, next: LuceneToken): boolean {
    const piece = (candidate: LuceneToken) =>
      candidate.type === 'term' || candidate.type === 'date' || candidate.type === 'wildcard';
    return piece(token) && piece(next);
  }

  private advance(): LuceneToken {
    const token = this.tokens[this.#cursor];
    this.#cursor += 1;
    return token;
  }
}

function readDateValue(value: string): string | null {
  const unquoted = normalizeTermValue(value);
  const match = /^(\d{4}-\d{2}-\d{2})(?:\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)?$/.exec(unquoted);
  return match ? match[1] : null;
}

function getDateLikeTermType(value: string): 'DateTerm' | 'TimeTerm' | 'DateTimeTerm' | null {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return 'DateTerm';
  }

  if (/^\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/.test(value)) {
    return 'TimeTerm';
  }

  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:?\d{2})$/.test(value)) {
    return 'DateTimeTerm';
  }

  return null;
}

function isLocalDateTimeValue(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/.test(value);
}

function normalizeTermValue(value: string): string {
  const quote = value[0];
  if ((quote !== '"' && quote !== "'") || value.at(-1) !== quote) {
    return unescapeTermValue(value);
  }

  return unescapeTermValue(value.slice(1, -1));
}

function unescapeTermValue(value: string): string {
  return value.replace(/\\(.)/g, '$1');
}
