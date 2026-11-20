import type { LuceneField, LuceneFieldValueOption } from '@identity/lucene-input'

import {
  AUDIT_ACTOR_TYPE_OPTIONS,
  AUDIT_ENTITY_TYPE_OPTIONS,
  AUDIT_EVENT_KIND_OPTIONS,
  AUDIT_OPERATION_OPTIONS,
  AUDIT_STATUS_OPTIONS,
  filterCatalogOptions,
  mergeActionOptions,
} from './audit-catalog'
import type { AuditValueKind } from './audit-labels'

export interface AuditFieldDescriptions {
  action: string
  actorType: string
  actor: string
  targetType: string
  target: string
  resourceType: string
  resource: string
  subject: string
  operation: string
  status: string
  previousStatus: string
  credentialType: string
  eventKind: string
  requestId: string
  traceId: string
  reason: string
  occurredAt: string
}

/** Localized display name for a stored enum value, shown beside completions. */
export type AuditValueLabeler = (kind: AuditValueKind, value: string) => string

export function buildAuditLuceneFields(
  descriptions: AuditFieldDescriptions,
  liveActions?: readonly string[],
  valueLabel?: AuditValueLabeler,
): LuceneField[] {
  const actionOptions = mergeActionOptions(liveActions)
  const labeled = (
    options: readonly LuceneFieldValueOption[],
    kind: AuditValueKind,
  ): readonly LuceneFieldValueOption[] => {
    if (!valueLabel) return options
    return options.map((option) => {
      const detail = valueLabel(kind, option.value)
      return detail === option.value ? option : { ...option, detail }
    })
  }
  const actorTypeOptions = labeled(AUDIT_ACTOR_TYPE_OPTIONS, 'actorType')
  const entityTypeOptions = labeled(AUDIT_ENTITY_TYPE_OPTIONS, 'entityType')
  const operationOptions = labeled(AUDIT_OPERATION_OPTIONS, 'operation')
  const statusOptions = labeled(AUDIT_STATUS_OPTIONS, 'status')
  const eventKindOptions = labeled(AUDIT_EVENT_KIND_OPTIONS, 'eventKind')

  return [
    {
      name: 'action',
      type: 'keyword',
      description: descriptions.action,
      search: async (query) => filterCatalogOptions(actionOptions, query),
    },
    {
      name: 'actorType',
      type: 'keyword',
      description: descriptions.actorType,
      search: async (query) => filterCatalogOptions(actorTypeOptions, query),
    },
    {
      name: 'actor',
      type: 'string',
      description: descriptions.actor,
    },
    {
      name: 'targetType',
      type: 'keyword',
      description: descriptions.targetType,
      search: async (query) => filterCatalogOptions(entityTypeOptions, query),
    },
    {
      name: 'target',
      type: 'string',
      description: descriptions.target,
    },
    {
      name: 'resourceType',
      type: 'keyword',
      description: descriptions.resourceType,
      search: async (query) => filterCatalogOptions(entityTypeOptions, query),
    },
    {
      name: 'resource',
      type: 'string',
      description: descriptions.resource,
    },
    {
      name: 'subject',
      type: 'string',
      description: descriptions.subject,
    },
    {
      name: 'operation',
      type: 'keyword',
      description: descriptions.operation,
      search: async (query) => filterCatalogOptions(operationOptions, query),
    },
    {
      name: 'status',
      type: 'keyword',
      description: descriptions.status,
      search: async (query) => filterCatalogOptions(statusOptions, query),
    },
    {
      name: 'previousStatus',
      type: 'keyword',
      description: descriptions.previousStatus,
    },
    {
      name: 'credentialType',
      type: 'keyword',
      description: descriptions.credentialType,
    },
    {
      name: 'eventKind',
      type: 'keyword',
      description: descriptions.eventKind,
      search: async (query) => filterCatalogOptions(eventKindOptions, query),
    },
    {
      name: 'requestId',
      type: 'string',
      description: descriptions.requestId,
    },
    {
      name: 'traceId',
      type: 'string',
      description: descriptions.traceId,
    },
    {
      name: 'reason',
      type: 'string',
      description: descriptions.reason,
    },
    {
      name: 'occurredAt',
      type: 'datetime',
      description: descriptions.occurredAt,
    },
  ]
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
