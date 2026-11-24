export { LuceneInput, type LuceneInputHandle, type LuceneInputProps } from './LuceneInput'
export { CompletionDropdown } from './CompletionDropdown'
export {
  createLuceneEditor,
  type LuceneEditorConfig,
  type LuceneEditorHandle
} from './lib/codemirror'
export type {
  LuceneCompletionDropdownState,
  CompletionAnchor
} from './lib/codemirror/completion-dropdown'
export { getLuceneDiagnostics } from './lib/diagnostics'
export type { LuceneProblem, LuceneProblemsState } from './lib/problems'
export { buildLuceneSyntaxTree } from './lib/syntax-tree'
export { tokenizeLuceneQuery, type LuceneToken, type LuceneTokenType } from './lib/syntax-highlighting'
export {
  evaluateDateMath,
  formatDateMathValue,
  formatDateValue,
  isDateMathValue
} from './lib/date-math'
export {
  localizeDiagnostic,
  localizeDiagnostics,
  localizeFieldType,
  localizeSyntaxCompletion
} from './lib/i18n'
export type {
  ComponentDiagnostic,
  DiagnosticSeverity,
  FieldValueSearch,
  FieldValueSearchContext,
  LuceneDiagnosticCode,
  LuceneDiagnosticsOptions,
  LuceneField,
  LuceneFieldType,
  LuceneFieldValueOption,
  LuceneInputChangeDetail,
  LuceneInputDiagnosticsDetail,
  LuceneInputMessages,
  LuceneInputSyntaxTreeDetail,
  LuceneSyntaxCompletionCode,
  LuceneSyntaxTree
} from './lib/types'
