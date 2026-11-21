import { getLuceneDiagnostics } from '@identity/lucene-input'
import { Skeleton } from '@identity/ui/components/skeleton'
import { useNavigate } from '@tanstack/react-router'
import { useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
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
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { AuditEventDetailSheet } from '../components/audit-event-detail-sheet'
import { AuditEventSentence, AuditOutcomeBadge } from '../components/audit-event-parts'
import { AuditQueryBar } from '../components/audit-query-bar'
import { useAuditEventDetail, useAuditEvents } from '../hooks/use-audit-events'
import { AUDIT_QUERY_ERROR_CODES, auditQueryValue } from '../lib/audit-catalog'
import { appendLuceneClause, buildAuditLuceneFields } from '../lib/audit-fields'
import { auditActionLabel } from '../lib/audit-presentation'
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

function AuditEventSummary({
  event,
  locale,
  onOpen,
}: {
  event: AuditEventFieldsFragment
  locale: string
  onOpen: () => void
}) {
  return (
    <button
      type="button"
      className="min-w-0 cursor-pointer text-left text-sm text-muted-foreground underline-offset-4 hover:underline"
      onClick={onOpen}
    >
      <AuditEventSentence event={event} locale={locale} />
    </button>
  )
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

  const fields = useMemo(() => buildAuditLuceneFields(t), [t])
  // A query that fails the shared syntax check is never sent; the query bar
  // explains it instead of the table showing a request failure.
  const appliedSyntaxError = useMemo(
    () =>
      applied.q
        ? getLuceneDiagnostics(applied.q, fields, locale, undefined, {
            disallowUnknownFields: true,
          }).find((item) => item.severity === 'error')?.message
        : undefined,
    [applied.q, fields, locale],
  )

  const variables = useMemo(
    () =>
      scope.read && !appliedSyntaxError
        ? auditEventsQueryVariables(appliedSearch, resolvedTimeZone, {
            includeActorUser: scope.readActorUser,
            includeActorClient: scope.readActorClient,
          })
        : null,
    [
      scope.read,
      scope.readActorUser,
      scope.readActorClient,
      appliedKey,
      resolvedTimeZone,
      appliedSyntaxError,
    ],
  )

  const eventsQuery = useAuditEvents(variables, scope.read)
  // Statement errors the server still rejects belong to the query bar too.
  const queryIssues = eventsQuery.errors.filter((issue) =>
    AUDIT_QUERY_ERROR_CODES.has(Number(issue.code)),
  )
  const queryRejected =
    Boolean(appliedSyntaxError) || (eventsQuery.status === 'error' && queryIssues.length > 0)

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

  // The detail adds the client application and the parsed device to the
  // listed event, which stays on screen while it loads.
  const detailQuery = useAuditEventDetail(
    search.event
      ? {
          id: search.event,
          includeActorUser: scope.readActorUser,
          includeActorClient: scope.readActorClient,
        }
      : null,
    scope.readDetail && Boolean(search.event),
  )

  const loadedDetail =
    detailQuery.data?.auditEvent?.id === search.event ? detailQuery.data?.auditEvent : undefined
  const activeDetailEvent = loadedDetail ?? cachedEvent

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
              appliedQueryError={
                // Only while the input still shows the applied query.
                (search.q?.trim() || undefined) === applied.q ? appliedSyntaxError : undefined
              }
              serverIssues={
                eventsQuery.partial
                  ? eventsQuery.errors
                  : queryRejected && queryIssues.length > 0
                    ? queryIssues
                    : undefined
              }
              requestId={
                eventsQuery.partial || queryIssues.length > 0 ? eventsQuery.requestId : undefined
              }
              traceId={
                eventsQuery.partial || queryIssues.length > 0 ? eventsQuery.traceId : undefined
              }
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
                queryRejected ? (
                  <AsyncState
                    kind="empty"
                    compact
                    title={t('auditInvalidQueryTitle')}
                    description={t('auditInvalidQueryDescription')}
                  />
                ) : eventsQuery.status === 'error' ? (
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
                  id: 'event',
                  label: t('auditColumnEvent'),
                  primary: true,
                  render: (event) => (
                    <AuditEventSummary
                      event={event}
                      locale={locale}
                      onOpen={() => go({ ...search, event: event.id }, { replace: false })}
                    />
                  ),
                },
                {
                  id: 'outcome',
                  label: t('auditColumnOutcome'),
                  render: (event) => <AuditOutcomeBadge event={event} />,
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
                  id: 'source',
                  label: t('auditColumnSource'),
                  render: (event) =>
                    event.ipAddress ? (
                      <span className="font-mono text-xs text-muted-foreground">
                        {event.ipAddress}
                      </span>
                    ) : null,
                },
                {
                  id: 'actions',
                  label: t('auditColumnActions'),
                  render: (event) => (
                    <TableRowActions
                      subject={auditActionLabel(event, t)}
                      actions={[
                        {
                          id: 'details',
                          label: t('auditActionViewDetails'),
                          onAction: () =>
                            go({ ...search, event: event.id }, { replace: false }),
                        },
                        {
                          id: 'filter-action',
                          label: t('auditFilterByAction'),
                          onAction: () => appendFilter('action', auditQueryValue(event.action)),
                        },
                        ...(event.actor.oid
                          ? [
                              {
                                id: 'filter-actor',
                                label: t('auditFilterByActor'),
                                onAction: () => appendFilter('actor', event.actor.oid!),
                              },
                            ]
                          : []),
                        ...(event.target
                          ? [
                              {
                                id: 'filter-target',
                                label: t('auditFilterByTarget'),
                                onAction: () => appendFilter('target', event.target!.oid),
                              },
                            ]
                          : []),
                        ...(event.ipAddress
                          ? [
                              {
                                id: 'filter-ip-address',
                                label: t('auditFilterByIpAddress'),
                                onAction: () => appendFilter('ipAddress', event.ipAddress!),
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
