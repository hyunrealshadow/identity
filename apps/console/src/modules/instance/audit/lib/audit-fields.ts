import type { LuceneField } from '@identity/lucene-input'

import type { MessageKey } from '#/lib/i18n'
import { auditValueOptions, filterCatalogOptions } from './audit-catalog'
import {
  AUDIT_ACTION_LABELS,
  AUDIT_ACTOR_KIND_LABELS,
  AUDIT_AUTH_METHOD_LABELS,
  AUDIT_CATEGORY_LABELS,
  AUDIT_FAILURE_REASON_LABELS,
  AUDIT_OUTCOME_LABELS,
  AUDIT_TARGET_KIND_LABELS,
} from './audit-labels'

type Translate = (key: MessageKey) => string

type FieldSpec = {
  name: string
  type: LuceneField['type']
  description: MessageKey
  values?: Readonly<Record<string, MessageKey>>
}

// Names match the backend query fields, which match the GraphQL AuditEvent fields.
const AUDIT_QUERY_FIELDS: readonly FieldSpec[] = [
  { name: 'category', type: 'keyword', description: 'auditFieldCategoryDesc', values: AUDIT_CATEGORY_LABELS },
  { name: 'action', type: 'keyword', description: 'auditFieldActionDesc', values: AUDIT_ACTION_LABELS },
  { name: 'outcome', type: 'keyword', description: 'auditFieldOutcomeDesc', values: AUDIT_OUTCOME_LABELS },
  { name: 'failureReason', type: 'keyword', description: 'auditFieldFailureReasonDesc', values: AUDIT_FAILURE_REASON_LABELS },
  { name: 'actorKind', type: 'keyword', description: 'auditFieldActorKindDesc', values: AUDIT_ACTOR_KIND_LABELS },
  { name: 'actor', type: 'string', description: 'auditFieldActorDesc' },
  { name: 'actorLabel', type: 'string', description: 'auditFieldActorLabelDesc' },
  { name: 'targetKind', type: 'keyword', description: 'auditFieldTargetKindDesc', values: AUDIT_TARGET_KIND_LABELS },
  { name: 'target', type: 'string', description: 'auditFieldTargetDesc' },
  { name: 'targetLabel', type: 'string', description: 'auditFieldTargetLabelDesc' },
  { name: 'client', type: 'string', description: 'auditFieldClientDesc' },
  { name: 'authMethod', type: 'keyword', description: 'auditFieldAuthMethodDesc', values: AUDIT_AUTH_METHOD_LABELS },
  { name: 'ipAddress', type: 'string', description: 'auditFieldIpAddressDesc' },
  { name: 'userAgent', type: 'string', description: 'auditFieldUserAgentDesc' },
  { name: 'requestId', type: 'string', description: 'auditFieldRequestIdDesc' },
  { name: 'traceId', type: 'string', description: 'auditFieldTraceIdDesc' },
  { name: 'occurredAt', type: 'datetime', description: 'auditFieldOccurredAtDesc' },
]

export function buildAuditLuceneFields(t: Translate): LuceneField[] {
  return AUDIT_QUERY_FIELDS.map((field) => {
    const options = field.values ? auditValueOptions(field.values, t) : null
    return {
      name: field.name,
      type: field.type,
      description: t(field.description),
      ...(options ? { search: async (query: string) => filterCatalogOptions(options, query) } : {}),
    }
  })
}

export function formatLuceneValue(value: string): string {
  const needsQuotes =
    value.length === 0 ||
    /[\s()[\]{}"'\\~^!:+<>/*?&|]/.test(value) ||
    value === 'AND' ||
    value === 'OR' ||
    value === 'NOT' ||
    value === 'TO'
  if (!needsQuotes) {
    return value
  }
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

export function appendLuceneClause(currentQuery: string, field: string, value: string): string {
  const formatted = `${field}:${formatLuceneValue(value)}`
  const trimmed = currentQuery.trim()
  if (!trimmed) {
    return formatted
  }
  if (trimmed.includes(formatted)) {
    return trimmed
  }
  return `${trimmed} AND ${formatted}`
}

export function applyTimeRangePreset(currentQuery: string, rangeExpr: string): string {
  const clause = `occurredAt:${rangeExpr}`
  const trimmed = currentQuery.trim()
  if (!trimmed) {
    return clause
  }
  const stripped = trimmed
    .replace(
      /(?:^|\s+)(?:AND\s+)?occurredAt:(?:\[[^\]]*\]|\{[^}]*\}|(?:>=|<=|>|<)?(?:"[^"]*"|\S+))/g,
      ' ',
    )
    .replace(/^\s*(?:AND\s+)+|(?:\s+AND)+\s*$/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim()
  if (!stripped) {
    return clause
  }
  return `${clause} AND ${stripped}`
}
