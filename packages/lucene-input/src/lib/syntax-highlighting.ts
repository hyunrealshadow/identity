import { RangeSetBuilder, type Extension } from '@identity/codemirror/state';
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate } from '@identity/codemirror/view';

export type LuceneTokenType =
  | 'field'
  | 'fieldSeparator'
  | 'operator'
  | 'date'
  | 'string'
  | 'regex'
  | 'wildcard'
  | 'punctuation'
  | 'term';

export type LuceneToken = {
  type: LuceneTokenType;
  from: number;
  to: number;
  text: string;
};

const tokenDecorations: Record<LuceneTokenType, Decoration> = {
  field: Decoration.mark({ class: 'lucene-token-field' }),
  fieldSeparator: Decoration.mark({ class: 'lucene-token-field-separator' }),
  operator: Decoration.mark({ class: 'lucene-token-operator' }),
  date: Decoration.mark({ class: 'lucene-token-date' }),
  string: Decoration.mark({ class: 'lucene-token-string' }),
  regex: Decoration.mark({ class: 'lucene-token-regex' }),
  wildcard: Decoration.mark({ class: 'lucene-token-wildcard' }),
  punctuation: Decoration.mark({ class: 'lucene-token-punctuation' }),
  term: Decoration.mark({ class: 'lucene-token-term' })
};

export function tokenizeLuceneQuery(value: string): LuceneToken[] {
  const tokens: LuceneToken[] = [];
  let index = 0;
  // `TO` is an operator only between the brackets of a range.
  let rangeDepth = 0;

  while (index < value.length) {
    const char = value[index];

    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    // `+term` and `-term`: required and prohibited clauses.
    if ((char === '+' || char === '-') && isPrefixPosition(value, index, tokens)) {
      tokens.push(createToken('operator', value, index, index + 1));
      index += 1;
      continue;
    }

    // `~` and `~2` (fuzzy) or `^2` (boost) after a term.
    if (char === '~' || char === '^') {
      const to = index + 1 + (/^\d+(?:\.\d+)?/.exec(value.slice(index + 1))?.[0].length ?? 0);
      tokens.push(createToken('operator', value, index, to));
      index = to;
      continue;
    }

    if (char === '"' || char === "'") {
      const to = readQuoted(value, index, char);
      const type = isQuotedDateLike(value.slice(index, to)) ? 'date' : 'string';
      tokens.push(createToken(type, value, index, to));
      index = to;
      continue;
    }

    if (char === '/') {
      const to = readRegex(value, index);
      tokens.push(createToken('regex', value, index, to));
      index = to;
      continue;
    }

    if (char === '&' && value[index + 1] === '&') {
      tokens.push(createToken('operator', value, index, index + 2));
      index += 2;
      continue;
    }

    if ((char === '>' || char === '<') && value[index + 1] === '=') {
      tokens.push(createToken('operator', value, index, index + 2));
      index += 2;
      continue;
    }

    if (char === '|' && value[index + 1] === '|') {
      tokens.push(createToken('operator', value, index, index + 2));
      index += 2;
      continue;
    }

    if (char === '>' || char === '<') {
      tokens.push(createToken('operator', value, index, index + 1));
      index += 1;
      continue;
    }

    if (char === '!') {
      tokens.push(createToken('operator', value, index, index + 1));
      index += 1;
      continue;
    }

    if (char === '*') {
      tokens.push(createToken('wildcard', value, index, index + 1));
      index += 1;
      continue;
    }

    if (char === ':' || char === '(' || char === ')' || char === '[' || char === ']' || char === '{' || char === '}') {
      if (char === '[' || char === '{') rangeDepth += 1;
      if (char === ']' || char === '}') rangeDepth = Math.max(0, rangeDepth - 1);
      const previous = tokens.at(-1);
      const type = char === ':' && previous?.type === 'field' ? 'fieldSeparator' : 'punctuation';
      tokens.push(createToken(type, value, index, index + 1));
      index += 1;
      continue;
    }

    const allowColon = shouldAllowColonInTerm(tokens);
    const to = readDateTime(value, index) ?? readTime(value, index) ?? readWord(value, index, allowColon);
    const text = value.slice(index, to);
    const next = nextNonWhitespace(value, to);
    const type =
      next === ':' && isFieldName(text)
        ? 'field'
        : isOperatorWord(text) || (rangeDepth > 0 && /^to$/i.test(text))
          ? 'operator'
          : isDateLike(text)
            ? 'date'
            : 'term';
    tokens.push(createToken(type, value, index, to));
    index = to;
  }

  return tokens;
}

export function luceneSyntaxHighlighting(): Extension {
  return [
    luceneSyntaxPlugin,
    EditorView.theme({
      '.lucene-token-field': {
        color: 'var(--lucene-token-field, #0b70db)',
        fontWeight: '600'
      },
      '.lucene-token-field-separator': {
        color: 'var(--muted-foreground)',
        fontWeight: '600'
      },
      '.lucene-token-operator': {
        color: 'var(--lucene-token-operator, #7c3aed)',
        fontWeight: '600'
      },
      '.lucene-token-date': {
        color: 'var(--foreground)'
      },
      '.lucene-token-string': {
        color: 'var(--lucene-token-string, #b45309)'
      },
      '.lucene-token-regex': {
        color: 'var(--destructive)'
      },
      '.lucene-token-wildcard': {
        color: 'var(--lucene-token-wildcard, #2563eb)',
        fontWeight: '600'
      },
      '.lucene-token-punctuation': {
        color: 'var(--muted-foreground)',
        fontWeight: '600'
      },
      '.lucene-token-term': {
        color: 'var(--foreground)'
      }
    })
  ];
}

const luceneSyntaxPlugin = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;

    constructor(view: EditorView) {
      this.decorations = buildDecorations(view);
    }

    update(update: ViewUpdate): void {
      if (update.docChanged || update.viewportChanged) {
        this.decorations = buildDecorations(update.view);
      }
    }
  },
  {
    decorations: (plugin) => plugin.decorations
  }
);

function buildDecorations(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  for (const token of tokenizeLuceneQuery(view.state.doc.toString())) {
    builder.add(token.from, token.to, tokenDecorations[token.type]);
  }

  return builder.finish();
}

function createToken(type: LuceneTokenType, value: string, from: number, to: number): LuceneToken {
  return {
    type,
    from,
    to,
    text: value.slice(from, to)
  };
}

function readQuoted(value: string, from: number, quote: string): number {
  for (let index = from + 1; index < value.length; index += 1) {
    if (value[index] === '\\') {
      index += 1;
      continue;
    }

    if (value[index] === quote) {
      return index + 1;
    }
  }

  return value.length;
}

function readRegex(value: string, from: number): number {
  for (let index = from + 1; index < value.length; index += 1) {
    if (value[index] === '\\') {
      index += 1;
      continue;
    }

    if (value[index] === '/') {
      return index + 1;
    }
  }

  return value.length;
}

function shouldAllowColonInTerm(tokens: LuceneToken[]): boolean {
  const previous = tokens.at(-1);
  if (!previous) {
    return false;
  }

  return (
    previous.type === 'fieldSeparator' ||
    previous.text === '[' ||
    previous.text === '{' ||
    /^(>=|<=|>|<)$/.test(previous.text) ||
    /^to$/i.test(previous.text)
  );
}

function readWord(value: string, from: number, allowColon = false): number {
  let index = from;
  const stopPattern = allowColon ? /[\s()[\]{}!*&|<>~^]/ : /[\s:()[\]{}!*&|<>~^]/;
  while (index < value.length && !stopPattern.test(value[index])) {
    if (value[index] === '\\') {
      index += 2;
    } else {
      index += 1;
    }
  }

  return index === from ? from + 1 : index;
}

function readDateTime(value: string, from: number): number | undefined {
  const match = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:?\d{2})/.exec(
    value.slice(from)
  );

  return match ? from + match[0].length : undefined;
}

function readTime(value: string, from: number): number | undefined {
  const match = /^\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?/.exec(value.slice(from));
  return match ? from + match[0].length : undefined;
}

function isQuotedDateLike(value: string): boolean {
  const quote = value[0];
  if ((quote !== '"' && quote !== "'") || value.at(-1) !== quote) {
    return false;
  }

  return isDateLike(value.slice(1, -1).replace(/\\(.)/g, '$1'));
}

function isDateLike(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}$/.test(value) ||
    /^\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/.test(value) ||
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/.test(value) ||
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:?\d{2})$/.test(value) ||
    /^now(?:[+-]\d+(?:ms|s|m|h|d|w|M|y))?(?:\/(?:s|m|h|d|w|M|y))?$/.test(value)
  );
}

/**
 * Whether a `+` or `-` here starts a clause rather than a value: it begins a
 * word, something follows it, and no field, comparison, or range is waiting
 * for a value (`actorLabel:-x` and `now-1d` keep their dash).
 */
function isPrefixPosition(value: string, index: number, tokens: LuceneToken[]): boolean {
  const next = value[index + 1];
  if (next === undefined || /\s/.test(next)) {
    return false;
  }
  if (index > 0 && !/[\s(]/.test(value[index - 1])) {
    return false;
  }
  const previous = tokens.at(-1);
  return !(
    previous &&
    (previous.type === 'fieldSeparator' ||
      /^(>=|<=|>|<|\[|\{)$/.test(previous.text) ||
      (previous.type === 'operator' && /^to$/i.test(previous.text)))
  );
}

function nextNonWhitespace(value: string, from: number): string | undefined {
  for (let index = from; index < value.length; index += 1) {
    if (!/\s/.test(value[index])) {
      return value[index];
    }
  }

  return undefined;
}

function isOperatorWord(text: string): boolean {
  return /^(AND|OR|NOT)$/i.test(text);
}

function isFieldName(text: string): boolean {
  return /^[A-Za-z_][\w.-]*$/.test(text);
}
