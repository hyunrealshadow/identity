import {
  AuditEventActionsQueryDocument,
  AuditEventDetailQueryDocument,
  AuditEventsQueryDocument,
  type AuditEventActionsQueryQuery,
  type AuditEventActionsQueryQueryVariables,
  type AuditEventDetailQueryQuery,
  type AuditEventDetailQueryQueryVariables,
  type AuditEventsQueryQuery,
  type AuditEventsQueryQueryVariables,
} from '#/generated/graphql'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

export function useAuditEvents(
  variables: AuditEventsQueryQueryVariables | null,
  enabled: boolean,
) {
  return useConsoleQuery<AuditEventsQueryQuery, AuditEventsQueryQueryVariables>(
    AuditEventsQueryDocument,
    variables,
    enabled && Boolean(variables),
    'missing_audit_events_connection',
    { keepPreviousData: true },
  )
}

export function useAuditEventDetail(
  variables: AuditEventDetailQueryQueryVariables | null,
  enabled: boolean,
) {
  return useConsoleQuery<AuditEventDetailQueryQuery, AuditEventDetailQueryQueryVariables>(
    AuditEventDetailQueryDocument,
    variables,
    enabled && Boolean(variables),
    'missing_audit_event_detail',
  )
}

export function useAuditEventActions(enabled: boolean) {
  return useConsoleQuery<AuditEventActionsQueryQuery, AuditEventActionsQueryQueryVariables>(
    AuditEventActionsQueryDocument,
    {},
    enabled,
    'missing_audit_event_actions',
  )
}
