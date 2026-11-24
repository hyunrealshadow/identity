import { describe, expect, it } from 'vitest';
import { tokenizeLuceneQuery } from './syntax-highlighting';

describe('lucene syntax highlighting tokenizer', () => {
  it('classifies fields, punctuation, operators, strings, regex, wildcard, and terms separately', () => {
    expect(tokenizeLuceneQuery('title:"hello" AND path:/src.*/ OR tag:*')).toEqual([
      { type: 'field', from: 0, to: 5, text: 'title' },
      { type: 'fieldSeparator', from: 5, to: 6, text: ':' },
      { type: 'string', from: 6, to: 13, text: '"hello"' },
      { type: 'operator', from: 14, to: 17, text: 'AND' },
      { type: 'field', from: 18, to: 22, text: 'path' },
      { type: 'fieldSeparator', from: 22, to: 23, text: ':' },
      { type: 'regex', from: 23, to: 30, text: '/src.*/' },
      { type: 'operator', from: 31, to: 33, text: 'OR' },
      { type: 'field', from: 34, to: 37, text: 'tag' },
      { type: 'fieldSeparator', from: 37, to: 38, text: ':' },
      { type: 'wildcard', from: 38, to: 39, text: '*' }
    ]);
  });

  it('classifies grouped negated terms', () => {
    expect(tokenizeLuceneQuery('!(status:closed)')).toEqual([
      { type: 'operator', from: 0, to: 1, text: '!' },
      { type: 'punctuation', from: 1, to: 2, text: '(' },
      { type: 'field', from: 2, to: 8, text: 'status' },
      { type: 'fieldSeparator', from: 8, to: 9, text: ':' },
      { type: 'term', from: 9, to: 15, text: 'closed' },
      { type: 'punctuation', from: 15, to: 16, text: ')' }
    ]);
  });

  it('classifies comparison operators separately from values', () => {
    expect(tokenizeLuceneQuery('score:>=10 score:<5')).toEqual([
      { type: 'field', from: 0, to: 5, text: 'score' },
      { type: 'fieldSeparator', from: 5, to: 6, text: ':' },
      { type: 'operator', from: 6, to: 8, text: '>=' },
      { type: 'term', from: 8, to: 10, text: '10' },
      { type: 'field', from: 11, to: 16, text: 'score' },
      { type: 'fieldSeparator', from: 16, to: 17, text: ':' },
      { type: 'operator', from: 17, to: 18, text: '<' },
      { type: 'term', from: 18, to: 19, text: '5' }
    ]);
  });

  it('keeps time-like field values together and tokenizes bracket ranges', () => {
    expect(tokenizeLuceneQuery('published_at:[09:00:00 TO 18:30:00]')).toEqual([
      { type: 'field', from: 0, to: 12, text: 'published_at' },
      { type: 'fieldSeparator', from: 12, to: 13, text: ':' },
      { type: 'punctuation', from: 13, to: 14, text: '[' },
      { type: 'date', from: 14, to: 22, text: '09:00:00' },
      { type: 'operator', from: 23, to: 25, text: 'TO' },
      { type: 'date', from: 26, to: 34, text: '18:30:00' },
      { type: 'punctuation', from: 34, to: 35, text: ']' }
    ]);
  });

  it('treats TO as an operator only inside a range', () => {
    const types = (query: string) =>
      tokenizeLuceneQuery(query)
        .filter((token) => /^to$/i.test(token.text))
        .map((token) => token.type);
    expect(types('occurredAt:[now-15m to now]')).toEqual(['operator']);
    expect(types('title:TO AND occurredAt:[now TO now] OR TO')).toEqual(['term', 'operator', 'term']);
  });

  it('keeps ISO datetime values together', () => {
    expect(tokenizeLuceneQuery('created_at:<=2024-01-01T09:00:00Z')).toEqual([
      { type: 'field', from: 0, to: 10, text: 'created_at' },
      { type: 'fieldSeparator', from: 10, to: 11, text: ':' },
      { type: 'operator', from: 11, to: 13, text: '<=' },
      { type: 'date', from: 13, to: 33, text: '2024-01-01T09:00:00Z' }
    ]);
  });

  it('classifies quoted local datetime values as date tokens', () => {
    expect(tokenizeLuceneQuery('created_at:"2026-05-15 10:21:43"')).toEqual([
      { type: 'field', from: 0, to: 10, text: 'created_at' },
      { type: 'fieldSeparator', from: 10, to: 11, text: ':' },
      { type: 'date', from: 11, to: 32, text: '"2026-05-15 10:21:43"' }
    ]);
  });

  it('treats unquoted datetime spaces as separate terms', () => {
    expect(tokenizeLuceneQuery('created_at:<=2024-01-01 09:00:00')).toEqual([
      { type: 'field', from: 0, to: 10, text: 'created_at' },
      { type: 'fieldSeparator', from: 10, to: 11, text: ':' },
      { type: 'operator', from: 11, to: 13, text: '<=' },
      { type: 'date', from: 13, to: 23, text: '2024-01-01' },
      { type: 'date', from: 24, to: 32, text: '09:00:00' }
    ]);
  });

  it('keeps escaped spaces inside unquoted terms', () => {
    expect(tokenizeLuceneQuery(String.raw`title:hello\ world created_at:2026-05-15\ 10:30:57`)).toEqual([
      { type: 'field', from: 0, to: 5, text: 'title' },
      { type: 'fieldSeparator', from: 5, to: 6, text: ':' },
      { type: 'term', from: 6, to: 18, text: String.raw`hello\ world` },
      { type: 'field', from: 19, to: 29, text: 'created_at' },
      { type: 'fieldSeparator', from: 29, to: 30, text: ':' },
      { type: 'term', from: 30, to: 50, text: String.raw`2026-05-15\ 10:30:57` }
    ]);
  });
});
