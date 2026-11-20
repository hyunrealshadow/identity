import { Badge } from '@identity/ui/components/badge'
import { Skeleton } from '@identity/ui/components/skeleton'
import { useNavigate } from '@tanstack/react-router'
import { useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
import { CopyableValue } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { PageHeader } from '#/components/page-header'
import { ResourceTable } from '#/components/resource-table'
import { StepUpPanel } from '#/components/step-up-panel'
import { TableRowActions } from '#/components/table-row-actions'
import type { AuditEventFieldsFragment } from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import { failureDescriptionKey, failureTitleKey } from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { resolveTimeZone } from '#/lib/time-zone'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useUrlFilters } from '#/lib/use-url-filters'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { AuditEventDetailSheet } from '../components/audit-event-detail-sheet'
import { AuditQueryBar } from '../components/audit-query-bar'
import { useAuditEventActions, useAuditEventDetail, useAuditEvents } from '../hooks/use-audit-events'
import { appendLuceneClause, buildAuditLuceneFields } from '../lib/audit-fields'
import { auditScope } from '../lib/audit-scope'
import {
  AUDIT_EVENTS_PAGE_SIZE,
  auditEventsAppliedFilters,
  auditEventsQueryKey,
  auditEventsQueryVariables,
  auditEventsSearchKey,
  type AuditEventsFilters,
  type AuditEventsSearch,
} from '../lib/audit-search'

function AuditEventsLoadingSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true">
      <Skeleton className="h-10 w-full" />
      <div className="space-y-2 rounded-lg border border-border p-4">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    </div>
  )
}

function summarizeActor(
  event: AuditEventFieldsFragment,
  locale: 'en-US' | 'zh-CN',
): string | null {
  if (event.actorUser) {
    return event.actorUser.nickname?.trim() || event.actorUser.username
  }
  if (event.actorClient) {
    return resolveLocalizedText(event.actorClient.names, locale) ?? event.actorClient.name
  }
  if (event.actorType && event.actorOid) {
    return `${event.actorType} (${event.actorOid.slice(0, 8)})`
  }
  return event.actorType ?? null
}

function summarizeTarget(event: AuditEventFieldsFragment): string | null {
  if (event.targetType && event.targetOid) {
    return `${event.targetType} (${event.targetOid.slice(0, 8)})`
  }
  return event.targetType ?? null
}

export function AuditEventsPage({ search }: { search: AuditEventsSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()

  const scope = useMemo(
    () => auditScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const resolvedTimeZone = useMemo(() => resolveTimeZone(timeZone), [timeZone])

  const { applied, go } = useUrlFilters<AuditEventsSearch, AuditEventsFilters>({
    search,
    keyOf: auditEventsSearchKey,
    appliedOf: auditEventsAppliedFilters,
    navigate: (next, { replace }) =>
      void navigate({ to: '/audit-events', search: next, replace }),
  })

  const appliedSearch: AuditEventsSearch = {
    ...applied,
    order: search.order,
    size: search.size,
    after: search.after,
    before: search.before,
  }
  const appliedKey = auditEventsQueryKey(appliedSearch)

  const variables = useMemo(
    () =>
      scope.read
        ? auditEventsQueryVariables(appliedSearch, resolvedTimeZone, {
            includeActorUser: scope.readActorUser,
            includeActorClient: scope.readActorClient,
          })
        : null,
    [scope.read, scope.readActorUser, scope.readActorClient, appliedKey, resolvedTimeZone],
  )

  const eventsQuery = useAuditEvents(variables, scope.read)
  const actionsQuery = useAuditEventActions(scope.read && scope.readActions)

  const fields = useMemo(
    () =>
      buildAuditLuceneFields(
        {
          action: t('auditFieldActionDesc'),
          actorType: t('auditFieldActorTypeDesc'),
          actor: t('auditFieldActorDesc'),
          targetType: t('auditFieldTargetTypeDesc'),
          target: t('auditFieldTargetDesc'),
          resourceType: t('auditFieldResourceTypeDesc'),
          resource: t('auditFieldResourceDesc'),
          subject: t('auditFieldSubjectDesc'),
          operation: t('auditFieldOperationDesc'),
          status: t('auditFieldStatusDesc'),
          previousStatus: t('auditFieldPreviousStatusDesc'),
          credentialType: t('auditFieldCredentialTypeDesc'),
          eventKind: t('auditFieldEventKindDesc'),
          requestId: t('auditFieldRequestIdDesc'),
          traceId: t('auditFieldTraceIdDesc'),
          reason: t('auditFieldReasonDesc'),
          occurredAt: t('auditFieldOccurredAtDesc'),
        },
        actionsQuery.data?.auditEventActions,
      ),
    [actionsQuery.data?.auditEventActions, t],
  )

  const connection = eventsQuery.data?.auditEvents
  const items = useMemo(
    () => (connection?.edges ?? []).map(({ node }) => node),
    [connection],
  )

  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      go({ ...search, after: undefined, before: undefined, ...cursor }),
  })

  const cachedEvent = useMemo(
    () => (search.event ? items.find((item) => item.id === search.event) : undefined),
    [items, search.event],
  )

  const detailQuery = useAuditEventDetail(
    search.event && !cachedEvent
      ? {
          id: search.event,
          includeActorUser: scope.readActorUser,
          includeActorClient: scope.readActorClient,
        }
      : null,
    scope.readDetail && Boolean(search.event) && !cachedEvent,
  )

  const activeDetailEvent = cachedEvent ?? detailQuery.data?.auditEvent

  function runSearch(nextQuery?: string) {
    const queryValue = (nextQuery ?? search.q)?.trim() || undefined
    const next: AuditEventsSearch = {
      ...search,
      q: queryValue,
      after: undefined,
      before: undefined,
    }
    if (auditEventsQueryKey(next) === appliedKey) {
      void eventsQuery.refresh()
    }
    go(next, { apply: { q: queryValue } })
  }

  function appendFilter(field: string, value: string) {
    const nextQuery = appendLuceneClause(search.q ?? '', field, value)
    const next: AuditEventsSearch = {
      ...search,
      q: nextQuery,
      event: undefined,
      after: undefined,
      before: undefined,
    }
    if (auditEventsQueryKey(next) === appliedKey) {
      void eventsQuery.refresh()
    }
    go(next, { apply: { q: nextQuery } })
  }

  return (
    <>
      <PageHeader title={t('auditTitle')} description={t('auditDescription')} />
      <ConsoleWorkspaceGate loading={<AuditEventsLoadingSkeleton />}>
        {!scope.read ? (
          <RbacAccessRestricted
            title="auditNoReadTitle"
            description="auditNoReadDescription"
            onBack={() => void navigate({ to: '/' })}
            backLabel="goHome"
          />
        ) : eventsQuery.stepUp ? (
          <StepUpPanel stepUp={eventsQuery.stepUp} hideDetails />
        ) : (
          <section className="space-y-5">
            <AuditQueryBar
              draftQuery={search.q ?? ''}
              onDraftChange={(nextValue) =>
                go({ ...search, q: nextValue || undefined }, { replace: true })
              }
              onSearch={runSearch}
              onClear={() => {
                const next: AuditEventsSearch = {
                  size: search.size,
                  order: search.order,
                }
                go(next, { apply: {} })
              }}
              fields={fields}
              locale={locale}
              timeZone={resolvedTimeZone}
              serverIssues={eventsQuery.partial ? eventsQuery.errors : undefined}
              requestId={eventsQuery.partial ? eventsQuery.requestId : undefined}
              traceId={eventsQuery.partial ? eventsQuery.traceId : undefined}
            />

            <ResourceTable
              id="audit-events"
              label={t('auditTableLabel')}
              filters={null}
              items={items}
              order={search.order ?? 'OCCURRED_AT_DESC'}
              onOrderChange={(order) =>
                go({
                  ...search,
                  order: order as AuditEventsSearch['order'],
                  after: undefined,
                  before: undefined,
                })
              }
              onRefresh={() => void eventsQuery.refresh()}
              refreshing={eventsQuery.refreshing || eventsQuery.status === 'loading'}
              emptyState={
                eventsQuery.status === 'error' ? (
                  <AsyncState
                    kind={eventsQuery.forbidden ? 'forbidden' : 'error'}
                    title={t(failureTitleKey(eventsQuery.failure, eventsQuery.forbidden))}
                    description={t(
                      failureDescriptionKey(eventsQuery.failure, eventsQuery.forbidden),
                    )}
                    requestId={eventsQuery.requestId}
                    traceId={eventsQuery.traceId}
                    issues={eventsQuery.errors}
                    onRetry={() => void eventsQuery.refresh()}
                  />
                ) : (
                  <AsyncState
                    kind="empty"
                    compact
                    title={t('auditEmptyTitle')}
                    description={t('auditEmptyDescription')}
                  />
                )
              }
              pagination={
                connection ? (
                  <CursorPagination
                    label={t('auditTableLabel')}
                    pageCount={connection.edges.length}
                    totalCount={connection.totalCount}
                    pageInfo={connection.pageInfo}
                    controller={pager}
                    isDisabled={eventsQuery.refreshing}
                    pageSize={search.size ?? AUDIT_EVENTS_PAGE_SIZE}
                    onPageSizeChange={(size) =>
                      go({ ...search, size, after: undefined, before: undefined })
                    }
                  />
                ) : null
              }
              columns={[
                {
                  id: 'action',
                  label: t('auditColumnAction'),
                  primary: true,
                  render: (event) => (
                    <button
                      type="button"
                      className="cursor-pointer text-left font-medium text-foreground underline-offset-4 hover:underline"
                      onClick={() =>
                        go({ ...search, event: event.id }, { replace: false })
                      }
                    >
                      {event.action ?? event.operation}
                    </button>
                  ),
                },
                {
                  id: 'occurredAt',
                  label: t('auditColumnOccurredAt'),
                  sort: 'OCCURRED_AT',
                  render: (event) => (
                    <span className="whitespace-nowrap text-sm">
                      {formatDateTime(event.occurredAt, locale, resolvedTimeZone)}
                    </span>
                  ),
                },
                {
                  id: 'actor',
                  label: t('auditColumnActor'),
                  render: (event) => {
                    const summary = summarizeActor(event, locale)
                    return summary ? (
                      <span className="text-sm">{summary}</span>
                    ) : null
                  },
                },
                {
                  id: 'target',
                  label: t('auditColumnTarget'),
                  render: (event) => {
                    const summary = summarizeTarget(event)
                    return summary ? (
                      <span className="text-sm">{summary}</span>
                    ) : null
                  },
                },
                {
                  id: 'operation',
                  label: t('auditColumnOperation'),
                  render: (event) => <span className="text-sm">{event.operation}</span>,
                },
                {
                  id: 'status',
                  label: t('auditColumnStatus'),
                  render: (event) =>
                    event.status ? <Badge variant="outline">{event.status}</Badge> : null,
                },
                {
                  id: 'requestId',
                  label: t('auditColumnRequestId'),
                  render: (event) =>
                    event.requestId ? (
                      <CopyableValue value={event.requestId} label={t('auditColumnRequestId')} />
                    ) : null,
                },
                {
                  id: 'actions',
                  label: t('auditColumnActions'),
                  render: (event) => (
                    <TableRowActions
                      subject={event.action ?? event.operation}
                      actions={[
                        {
                          id: 'details',
                          label: t('auditActionViewDetails'),
                          onAction: () =>
                            go({ ...search, event: event.id }, { replace: false }),
                        },
                        ...(event.action
                          ? [
                              {
                                id: 'filter-action',
                                label: t('auditFilterByAction'),
                                onAction: () => appendFilter('action', event.action!),
                              },
                            ]
                          : []),
                        ...(event.actorOid
                          ? [
                              {
                                id: 'filter-actor',
                                label: t('auditFilterByActor'),
                                onAction: () => appendFilter('actor', event.actorOid!),
                              },
                            ]
                          : []),
                        ...(event.requestId
                          ? [
                              {
                                id: 'filter-request-id',
                                label: t('auditFilterByRequestId'),
                                onAction: () => appendFilter('requestId', event.requestId!),
                              },
                            ]
                          : []),
                      ]}
                    />
                  ),
                },
              ]}
            />

            <AuditEventDetailSheet
              open={Boolean(search.event)}
              onOpenChange={(nextOpen) => {
                if (!nextOpen) {
                  go({ ...search, event: undefined }, { replace: true })
                }
              }}
              event={activeDetailEvent}
              loading={!cachedEvent && detailQuery.status === 'loading'}
              error={
                !cachedEvent && detailQuery.status === 'error'
                  ? {
                      kind: detailQuery.forbidden ? 'forbidden' : 'error',
                      title: t(failureTitleKey(detailQuery.failure, detailQuery.forbidden)),
                      description: t(
                        failureDescriptionKey(detailQuery.failure, detailQuery.forbidden),
                      ),
                      issues: detailQuery.errors,
                      requestId: detailQuery.requestId,
                      traceId: detailQuery.traceId,
                    }
                  : null
              }
              onRetry={() => void detailQuery.refresh()}
              onAppendFilter={appendFilter}
            />
          </section>
        )}
      </ConsoleWorkspaceGate>
    </>
  )
}
