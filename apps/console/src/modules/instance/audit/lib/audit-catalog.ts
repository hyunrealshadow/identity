import { AuditErrorCode } from '@identity/graphql-access'
import type { LuceneFieldValueOption } from '@identity/lucene-input'

import type { MessageKey } from '#/lib/i18n'

/** Server error codes that reject the query statement itself. */
export const AUDIT_QUERY_ERROR_CODES: ReadonlySet<number> = new Set([
  AuditErrorCode.QueryTooLong,
  AuditErrorCode.QueryTooManyClauses,
  AuditErrorCode.QueryTooDeep,
  AuditErrorCode.QuerySyntaxError,
  AuditErrorCode.QueryUnknownField,
  AuditErrorCode.QueryInvalidDate,
  AuditErrorCode.QueryInvalidIdentifier,
  AuditErrorCode.QueryUnsupportedOperator,
  AuditErrorCode.QueryUnsupportedRangeField,
  AuditErrorCode.QueryUnsupportedRegex,
  AuditErrorCode.QueryUnsupportedSyntax,
  AuditErrorCode.QueryUnknownValue,
])

/**
 * The stored and Lucene form of a schema enum value: the same name in lower
 * case, such as `USER_CREATE` → `user_create`.
 */
export function auditQueryValue(value: string): string {
  return value.toLowerCase()
}

/** Completion options for one enumerated field, from its typed label table. */
export function auditValueOptions(
  labels: Readonly<Record<string, MessageKey>>,
  t: (key: MessageKey) => string,
): LuceneFieldValueOption[] {
  return Object.entries(labels)
    .map(([value, key]) => ({
      label: auditQueryValue(value),
      value: auditQueryValue(value),
      detail: t(key),
    }))
    .sort((a, b) => a.label.localeCompare(b.label))
}

export function filterCatalogOptions(
  options: readonly LuceneFieldValueOption[],
  query: string,
): LuceneFieldValueOption[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return [...options]
  return options.filter(
    (option) =>
      option.label.toLowerCase().includes(needle) ||
      Boolean(option.detail?.toLowerCase().includes(needle)),
  )
}
