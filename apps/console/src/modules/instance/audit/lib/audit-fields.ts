import type { LuceneField } from '@identity/lucene-input'

import {
  AUDIT_ACTOR_TYPE_OPTIONS,
  AUDIT_ENTITY_TYPE_OPTIONS,
  AUDIT_EVENT_KIND_OPTIONS,
  AUDIT_OPERATION_OPTIONS,
  AUDIT_STATUS_OPTIONS,
  filterCatalogOptions,
  mergeActionOptions,
} from './audit-catalog'

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

export function buildAuditLuceneFields(
  descriptions: AuditFieldDescriptions,
  liveActions?: readonly string[],
): LuceneField[] {
  const actionOptions = mergeActionOptions(liveActions)

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
      search: async (query) => filterCatalogOptions(AUDIT_ACTOR_TYPE_OPTIONS, query),
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
      search: async (query) => filterCatalogOptions(AUDIT_ENTITY_TYPE_OPTIONS, query),
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
      search: async (query) => filterCatalogOptions(AUDIT_ENTITY_TYPE_OPTIONS, query),
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
      search: async (query) => filterCatalogOptions(AUDIT_OPERATION_OPTIONS, query),
    },
    {
      name: 'status',
      type: 'keyword',
      description: descriptions.status,
      search: async (query) => filterCatalogOptions(AUDIT_STATUS_OPTIONS, query),
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
      search: async (query) => filterCatalogOptions(AUDIT_EVENT_KIND_OPTIONS, query),
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
