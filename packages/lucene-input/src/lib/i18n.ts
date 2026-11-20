import type {
  ComponentDiagnostic,
  LuceneDiagnosticCode,
  LuceneFieldType,
  LuceneInputMessages,
  LuceneSyntaxCompletionCode
} from './types';

type DiagnosticDictionary = Record<LuceneDiagnosticCode, string>;
type FieldTypeDictionary = Record<LuceneFieldType, string>;
type SyntaxCompletionDictionary = Record<LuceneSyntaxCompletionCode, string>;

const en: DiagnosticDictionary = {
  unexpectedToken: '"{token}" cannot be used here',
  missingToken: 'Add more search text here',
  unclosedGroup: 'Add a closing ")" to finish this group',
  unknownField: 'Cannot search with "{field}:"',
  invalidFieldValue: 'This value does not work for "{field}"',
  fieldValueSearchFailed: 'Suggestions for "{field}" could not be loaded'
};

const zhCN: DiagnosticDictionary = {
  unexpectedToken: '不能在这里使用 "{token}"',
  missingToken: '请在这里继续输入搜索内容',
  unclosedGroup: '请添加 ")" 来结束这个分组',
  unknownField: '不能使用 "{field}:" 进行搜索',
  invalidFieldValue: '"{field}" 的这个值不可用',
  fieldValueSearchFailed: '无法加载 "{field}" 的建议'
};

const dictionaries: Record<string, DiagnosticDictionary> = {
  en,
  'en-US': en,
  'zh-CN': zhCN,
  zh: zhCN
};

const enFieldTypes: FieldTypeDictionary = {
  string: 'String',
  number: 'Number',
  date: 'Date',
  time: 'Time',
  datetime: 'Date time',
  boolean: 'Boolean',
  keyword: 'Keyword'
};

const zhCNFieldTypes: FieldTypeDictionary = {
  string: '文本',
  number: '数字',
  date: '日期',
  time: '时间',
  datetime: '日期时间',
  boolean: '布尔',
  keyword: '关键字'
};

const fieldTypeDictionaries: Record<string, FieldTypeDictionary> = {
  en: enFieldTypes,
  'en-US': enFieldTypes,
  'zh-CN': zhCNFieldTypes,
  zh: zhCNFieldTypes
};

const enSyntaxCompletions: SyntaxCompletionDictionary = {
  operator: 'Operator',
  group: 'Group',
  andDescription: 'Match both sides.',
  orDescription: 'Match either side.',
  notDescription: 'Negate the next term.',
  openGroupDescription: 'Start a grouped expression.',
  closeGroupDescription: 'End a grouped expression.',
  comparisonDescription: 'Compare this field with a value.',
  rangeDescription: 'Search between two values.',
  dateExampleDescription: 'Date format',
  timeExampleDescription: 'Time format',
  datetimeExampleDescription: 'Date and time format',
  isoDatetimeExampleDescription: 'ISO 8601 format',
  relativeTimeDescription: 'Relative time',
  normalizedDateDescription: 'Completed date',
  todayLabel: 'Today',
  nowLabel: 'Now',
  last5MinutesLabel: 'Last 5 minutes',
  last10MinutesLabel: 'Last 10 minutes',
  last15MinutesLabel: 'Last 15 minutes',
  last30MinutesLabel: 'Last 30 minutes',
  lastHourLabel: 'Last hour',
  last24HoursLabel: 'Last 24 hours',
  last7DaysLabel: 'Last 7 days',
  last30DaysLabel: 'Last 30 days',
  completionPreview: 'Completes to {value}'
};

const zhCNSyntaxCompletions: SyntaxCompletionDictionary = {
  operator: '操作符',
  group: '分组',
  andDescription: '同时匹配两侧',
  orDescription: '匹配任意一侧',
  notDescription: '排除后面的条件',
  openGroupDescription: '开始一个分组表达式',
  closeGroupDescription: '结束一个分组表达式',
  comparisonDescription: '和一个值比较',
  rangeDescription: '搜索两个值之间',
  dateExampleDescription: '日期格式',
  timeExampleDescription: '时间格式',
  datetimeExampleDescription: '日期时间格式',
  isoDatetimeExampleDescription: 'ISO 8601 格式',
  relativeTimeDescription: '相对时间',
  normalizedDateDescription: '补全后的日期',
  todayLabel: '今天',
  nowLabel: '现在',
  last5MinutesLabel: '过去 5 分钟',
  last10MinutesLabel: '过去 10 分钟',
  last15MinutesLabel: '过去 15 分钟',
  last30MinutesLabel: '过去 30 分钟',
  lastHourLabel: '过去 1 小时',
  last24HoursLabel: '过去 24 小时',
  last7DaysLabel: '过去 7 天',
  last30DaysLabel: '过去 30 天',
  completionPreview: '补全为 {value}'
};

const syntaxCompletionDictionaries: Record<string, SyntaxCompletionDictionary> = {
  en: enSyntaxCompletions,
  'en-US': enSyntaxCompletions,
  'zh-CN': zhCNSyntaxCompletions,
  zh: zhCNSyntaxCompletions
};

export function localizeDiagnostic(
  diagnostic: ComponentDiagnostic,
  locale = 'en',
  messages?: LuceneInputMessages
): ComponentDiagnostic {
  const template = messages?.diagnostics?.[diagnostic.code] ?? getBuiltInDiagnosticTemplate(diagnostic, locale);

  return {
    ...diagnostic,
    message: interpolate(template, diagnostic.params)
  };
}

function getBuiltInDiagnosticTemplate(diagnostic: ComponentDiagnostic, locale: string): string {
  if (diagnostic.code === 'missingToken') {
    const expected = diagnostic.params?.expected;
    if (expected === 'field value') {
      return locale.startsWith('zh') ? '请在 {field}: 后输入搜索内容' : 'Enter search text after {field}:';
    }

    if (expected === 'term') {
      return locale.startsWith('zh')
        ? '请在 {operator} 后输入另一个搜索条件'
        : 'Enter another search condition after {operator}';
    }
  }

  if (diagnostic.code === 'invalidFieldValue') {
    const expected = diagnostic.params?.expected;
    if (diagnostic.params?.repairable) {
      if (expected === 'date') {
        return locale.startsWith('zh') ? '按 Tab 补全 {field} 的日期' : 'Press Tab to complete the date for {field}';
      }

      if (expected === 'datetime') {
        return locale.startsWith('zh')
          ? '按 Tab 补全 {field} 的日期时间'
          : 'Press Tab to complete the date and time for {field}';
      }
    }

    if (expected === 'number') {
      return locale.startsWith('zh') ? '{field} 需要输入数字' : 'Enter a number for {field}';
    }

    if (expected === 'date') {
      return locale.startsWith('zh')
        ? '{field} 需要输入合法日期：YYYY-MM-DD 或 now/d'
        : 'Use a valid date for {field}: YYYY-MM-DD or now/d';
    }

    if (expected === 'time') {
      return locale.startsWith('zh') ? '{field} 需要输入合法时间：HH:mm:ss' : 'Use a valid time for {field}: HH:mm:ss';
    }

    if (expected === 'datetime') {
      return locale.startsWith('zh')
        ? '{field} 需要输入合法日期时间："YYYY-MM-DD HH:mm:ss"、YYYY-MM-DDTHH:mm:ssZ 或 now-5m'
        : 'Use a valid datetime for {field}: "YYYY-MM-DD HH:mm:ss", YYYY-MM-DDTHH:mm:ssZ, or now-5m';
    }
  }

  return dictionaries[locale]?.[diagnostic.code] ?? dictionaries.en[diagnostic.code] ?? diagnostic.message;
}

export function localizeDiagnostics(
  diagnostics: ComponentDiagnostic[],
  locale = 'en',
  messages?: LuceneInputMessages
): ComponentDiagnostic[] {
  return diagnostics.map((diagnostic) => localizeDiagnostic(diagnostic, locale, messages));
}

export function localizeFieldType(
  fieldType: LuceneFieldType,
  locale = 'en',
  messages?: LuceneInputMessages
): string {
  return messages?.fieldTypes?.[fieldType] ?? fieldTypeDictionaries[locale]?.[fieldType] ?? enFieldTypes[fieldType];
}

export function localizeSyntaxCompletion(
  code: LuceneSyntaxCompletionCode,
  locale = 'en',
  messages?: LuceneInputMessages
): string {
  return (
    messages?.syntaxCompletions?.[code] ??
    syntaxCompletionDictionaries[locale]?.[code] ??
    enSyntaxCompletions[code]
  );
}

export function localizeCompletionPreview(
  value: string,
  locale = 'en',
  messages?: LuceneInputMessages
): string {
  return interpolate(localizeSyntaxCompletion('completionPreview', locale, messages), { value });
}

function interpolate(template: string, params: ComponentDiagnostic['params'] = {}): string {
  return template.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = params[key];
    return value === undefined ? '' : String(value);
  });
}
