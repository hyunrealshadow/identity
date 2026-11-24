export const diagnosticCodes = [
  'unexpectedToken',
  'missingToken',
  'unclosedGroup',
  'unknownField',
  'invalidFieldValue',
  'fieldValueSearchFailed'
] as const;

export type LuceneDiagnosticCode = (typeof diagnosticCodes)[number];

export type LuceneFieldType = 'string' | 'number' | 'date' | 'time' | 'datetime' | 'boolean' | 'keyword';

export type LuceneSyntaxCompletionCode =
  | 'operator'
  | 'group'
  | 'andDescription'
  | 'orDescription'
  | 'notDescription'
  | 'openGroupDescription'
  | 'closeGroupDescription'
  | 'comparisonDescription'
  | 'rangeDescription'
  | 'dateExampleDescription'
  | 'timeExampleDescription'
  | 'datetimeExampleDescription'
  | 'isoDatetimeExampleDescription'
  | 'relativeTimeDescription'
  | 'normalizedDateDescription'
  | 'todayLabel'
  | 'nowLabel'
  | 'last5MinutesLabel'
  | 'last10MinutesLabel'
  | 'last15MinutesLabel'
  | 'last30MinutesLabel'
  | 'lastHourLabel'
  | 'last24HoursLabel'
  | 'last7DaysLabel'
  | 'last30DaysLabel'
  | 'completionPreview'
  | 'problemsSection'
  | 'errorLabel'
  | 'warningLabel'
  | 'infoLabel'
  | 'fieldsSection'
  | 'syntaxSection'
  | 'valuesSection'
  | 'addAction'
  | 'historyHint'
  | 'historySection';

export type LuceneFieldValueOption = {
  label: string;
  value: string;
  detail?: string;
  description?: string;
};

export type LuceneField = {
  name: string;
  type?: LuceneFieldType;
  description?: string;
  search?: FieldValueSearch;
};

export type FieldValueSearchContext = {
  field: LuceneField;
  value: string;
  position: number;
  signal: AbortSignal;
};

export type FieldValueSearch = (
  query: string,
  context: FieldValueSearchContext
) => Promise<LuceneFieldValueOption[]>;

export type DiagnosticSeverity = 'error' | 'warning' | 'info';

export type ComponentDiagnostic = {
  code: LuceneDiagnosticCode;
  message: string;
  severity: DiagnosticSeverity;
  from: number;
  to: number;
  params?: Record<string, string | number | boolean | undefined>;
};

export type LuceneInputMessages = {
  diagnostics?: Partial<Record<LuceneDiagnosticCode, string>>;
  fieldTypes?: Partial<Record<LuceneFieldType, string>>;
  syntaxCompletions?: Partial<Record<LuceneSyntaxCompletionCode, string>>;
};

export type LuceneInputChangeDetail = {
  value: string;
};

export type LuceneInputDiagnosticsDetail = {
  diagnostics: ComponentDiagnostic[];
};

export type LuceneSyntaxTree = {
  type: string;
  operator?: string;
  value?: string;
  from?: number;
  to?: number;
  children?: LuceneSyntaxTree[];
};

export type LuceneInputSyntaxTreeDetail = {
  syntaxTree: LuceneSyntaxTree;
};

export type LuceneDiagnosticsOptions = {
  disallowUnknownFields?: boolean;
};
