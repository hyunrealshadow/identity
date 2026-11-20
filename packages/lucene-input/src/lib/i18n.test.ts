import { describe, expect, it } from 'vitest';
import { localizeDiagnostic, localizeFieldType, localizeSyntaxCompletion } from './i18n';
import type { ComponentDiagnostic, LuceneInputMessages } from './types';

const unknownFieldDiagnostic: ComponentDiagnostic = {
  code: 'unknownField',
  message: '',
  severity: 'warning',
  from: 0,
  to: 6,
  params: { field: 'authorx' }
};

describe('diagnostic i18n', () => {
  it('uses English messages by default', () => {
    expect(localizeDiagnostic(unknownFieldDiagnostic).message).toBe('Cannot search with "authorx:"');
  });

  it('uses Simplified Chinese messages when locale is zh-CN', () => {
    expect(localizeDiagnostic(unknownFieldDiagnostic, 'zh-CN').message).toBe('不能使用 "authorx:" 进行搜索');
  });

  it('interpolates diagnostic parameters', () => {
    const diagnostic: ComponentDiagnostic = {
      code: 'missingToken',
      message: '',
      severity: 'error',
      from: 4,
      to: 4,
      params: { expected: ')' }
    };

    expect(localizeDiagnostic(diagnostic, 'en').message).toBe('Add more search text here');
  });

  it('uses friendly messages for missing search content', () => {
    expect(
      localizeDiagnostic(
        {
          code: 'missingToken',
          message: '',
          severity: 'error',
          from: 0,
          to: 0,
          params: { expected: 'field value', field: 'author' }
        },
        'zh-CN'
      ).message
    ).toBe('请在 author: 后输入搜索内容');

    expect(
      localizeDiagnostic(
        {
          code: 'missingToken',
          message: '',
          severity: 'error',
          from: 0,
          to: 0,
          params: { expected: 'term', operator: 'AND' }
        },
        'zh-CN'
      ).message
    ).toBe('请在 AND 后输入另一个搜索条件');
  });

  it('lets consumers override built-in messages', () => {
    const messages: LuceneInputMessages = {
      diagnostics: {
        unknownField: 'Field {field} is not allowed here'
      }
    };

    expect(localizeDiagnostic(unknownFieldDiagnostic, 'zh-CN', messages).message).toBe(
      'Field authorx is not allowed here'
    );
  });

  it('localizes field type labels', () => {
    expect(localizeFieldType('keyword', 'en')).toBe('Keyword');
    expect(localizeFieldType('keyword', 'zh-CN')).toBe('关键字');
    expect(localizeFieldType('time', 'zh-CN')).toBe('时间');
    expect(localizeFieldType('datetime', 'zh-CN')).toBe('日期时间');
  });

  it('lets consumers override field type labels', () => {
    expect(
      localizeFieldType('keyword', 'zh-CN', {
        fieldTypes: {
          keyword: '枚举'
        }
      })
    ).toBe('枚举');
  });

  it('localizes syntax completion labels', () => {
    expect(localizeSyntaxCompletion('operator', 'en')).toBe('Operator');
    expect(localizeSyntaxCompletion('operator', 'zh-CN')).toBe('操作符');
    expect(localizeSyntaxCompletion('andDescription', 'zh-CN')).toBe('同时匹配两侧');
    expect(localizeSyntaxCompletion('datetimeExampleDescription', 'zh-CN')).toBe('日期时间格式');
    expect(localizeSyntaxCompletion('isoDatetimeExampleDescription', 'zh-CN')).toBe('ISO 8601 格式');
    expect(localizeSyntaxCompletion('relativeTimeDescription', 'zh-CN')).toBe('相对时间');
    expect(localizeSyntaxCompletion('normalizedDateDescription', 'zh-CN')).toBe('补全后的日期');
  });

  it('lets consumers override syntax completion labels', () => {
    expect(
      localizeSyntaxCompletion('operator', 'zh-CN', {
        syntaxCompletions: {
          operator: '逻辑'
        }
      })
    ).toBe('逻辑');
  });
});
