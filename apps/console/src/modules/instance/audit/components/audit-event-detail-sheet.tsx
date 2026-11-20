import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@identity/ui/components/sheet'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Link } from '@tanstack/react-router'
import { Filter } from 'lucide-react'
import type { ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { CopyableValue } from '#/components/copy-button'
import type { AuditEventFieldsFragment } from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useLocale, useTranslator } from '#/lib/i18n'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'

export interface AuditEventDetailSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  event: AuditEventFieldsFragment | null | undefined
  loading?: boolean
  error?: {
    kind: 'error' | 'forbidden'
    title: string
    description: string
    issues?: ReadonlyArray<GraphQLIssue>
    requestId?: string
    traceId?: string
  } | null
  onRetry?: () => void
  onAppendFilter: (field: string, value: string) => void
}

function DetailRow({
  label,
  value,
  filterAction,
}: {
  label: string
  value: ReactNode
  filterAction?: { label: string; onClick: () => void }
}) {
  if (value === null || value === undefined || value === '') {
    return null
  }
  return (
    <div className="flex flex-col gap-1 border-b border-border/60 py-2.5 last:border-b-0 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <dt className="shrink-0 text-xs font-medium text-muted-foreground sm:w-36">{label}</dt>
      <dd className="flex min-w-0 flex-1 flex-wrap items-center justify-between gap-2 text-sm text-foreground break-all">
        <div className="min-w-0">{value}</div>
        {filterAction ? (
          <Button
            type="button"
            size="xs"
            variant="ghost"
            className="shrink-0"
            onClick={filterAction.onClick}
          >
            <Filter className="size-3" aria-hidden="true" />
            {filterAction.label}
          </Button>
        ) : null}
      </dd>
    </div>
  )
}

export function AuditEventDetailSheet({
  open,
  onOpenChange,
  event,
  loading = false,
  error = null,
  onRetry,
  onAppendFilter,
}: AuditEventDetailSheetProps) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()

  const actorDisplay = (() => {
    if (!event) return null
    if (event.actorUser) {
      const label = event.actorUser.nickname?.trim() || event.actorUser.username
      return (
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to="/users/$userId"
            params={{ userId: event.actorUser.id }}
            className="font-medium underline-offset-4 hover:underline"
          >
            {label}
          </Link>
          <span className="text-xs text-muted-foreground">{event.actorUser.email}</span>
        </div>
      )
    }
    if (event.actorClient) {
      const label = resolveLocalizedText(event.actorClient.names, locale) ?? event.actorClient.name
      return (
        <Link
          to="/clients/$clientId"
          params={{ clientId: event.actorClient.id }}
          className="font-medium underline-offset-4 hover:underline"
        >
          {label}
        </Link>
      )
    }
    return null
  })()

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        closeLabel={t('auditDetailClose')}
        className="w-full overflow-y-auto sm:max-w-xl"
      >
        <SheetHeader className="border-b border-border pb-4">
          <SheetTitle>
            {event ? (event.action ?? event.operation) : t('auditDetailTitle')}
          </SheetTitle>
          <SheetDescription>
            {event ? formatDateTime(event.occurredAt, locale, timeZone) : t('auditDescription')}
          </SheetDescription>
        </SheetHeader>

        <div className="mt-5 space-y-6">
          {loading ? (
            <div className="space-y-4" aria-busy="true">
              <Skeleton className="h-5 w-40" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : error ? (
            <AsyncState
              kind={error.kind}
              title={error.title}
              description={error.description}
              issues={error.issues}
              requestId={error.requestId}
              traceId={error.traceId}
              onRetry={onRetry}
            />
          ) : !event ? (
            <AsyncState
              kind="empty"
              compact
              title={t('auditDetailUnavailable')}
              description={t('auditDetailUnavailableDescription')}
            />
          ) : (
            <>
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t('auditDetailSectionSummary')}
                </h3>
                <dl className="divide-y divide-border/60 rounded-lg border border-border px-3.5">
                  <DetailRow
                    label={t('auditDetailOccurredAt')}
                    value={formatDateTime(event.occurredAt, locale, timeZone)}
                  />
                  <DetailRow
                    label={t('auditDetailAction')}
                    value={event.action ? <code className="font-mono text-xs">{event.action}</code> : null}
                    filterAction={
                      event.action
                        ? {
                            label: t('auditFilterByAction'),
                            onClick: () => onAppendFilter('action', event.action!),
                          }
                        : undefined
                    }
                  />
                  <DetailRow label={t('auditDetailOperation')} value={event.operation} />
                  <DetailRow
                    label={t('auditDetailStatus')}
                    value={
                      event.status ? <Badge variant="outline">{event.status}</Badge> : null
                    }
                  />
                  <DetailRow
                    label={t('auditDetailPreviousStatus')}
                    value={event.previousStatus}
                  />
                  <DetailRow label={t('auditDetailEventKind')} value={event.eventKind} />
                  <DetailRow label={t('auditDetailCredentialType')} value={event.credentialType} />
                  <DetailRow label={t('auditDetailReason')} value={event.reason} />
                  <DetailRow
                    label={t('auditDetailEventId')}
                    value={<CopyableValue value={event.id} label={t('auditDetailEventId')} />}
                  />
                  <DetailRow
                    label={t('auditDetailTransactionId')}
                    value={<code className="font-mono text-xs">{event.transactionId}</code>}
                  />
                </dl>
              </section>

              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t('auditDetailSectionActorTarget')}
                </h3>
                <dl className="divide-y divide-border/60 rounded-lg border border-border px-3.5">
                  <DetailRow label={t('auditDetailActorType')} value={event.actorType} />
                  <DetailRow label={t('auditDetailActorIdentity')} value={actorDisplay} />
                  <DetailRow
                    label={t('auditDetailActorOid')}
                    value={
                      event.actorOid ? (
                        <CopyableValue value={event.actorOid} label={t('auditDetailActorOid')} />
                      ) : null
                    }
                    filterAction={
                      event.actorOid
                        ? {
                            label: t('auditFilterByActor'),
                            onClick: () => onAppendFilter('actor', event.actorOid!),
                          }
                        : undefined
                    }
                  />
                  <DetailRow
                    label={t('auditDetailActorGlobalId')}
                    value={
                      event.actorGlobalId ? (
                        <CopyableValue
                          value={event.actorGlobalId}
                          label={t('auditDetailActorGlobalId')}
                        />
                      ) : null
                    }
                  />
                  <DetailRow label={t('auditDetailTargetType')} value={event.targetType} />
                  <DetailRow
                    label={t('auditDetailTargetOid')}
                    value={
                      event.targetOid ? (
                        <CopyableValue value={event.targetOid} label={t('auditDetailTargetOid')} />
                      ) : null
                    }
                    filterAction={
                      event.targetOid
                        ? {
                            label: t('auditFilterByTarget'),
                            onClick: () => onAppendFilter('target', event.targetOid!),
                          }
                        : undefined
                    }
                  />
                  <DetailRow
                    label={t('auditDetailTargetGlobalId')}
                    value={
                      event.targetGlobalId ? (
                        <CopyableValue
                          value={event.targetGlobalId}
                          label={t('auditDetailTargetGlobalId')}
                        />
                      ) : null
                    }
                  />
                  <DetailRow label={t('auditDetailResourceType')} value={event.resourceType} />
                  <DetailRow
                    label={t('auditDetailResourceOid')}
                    value={
                      <CopyableValue
                        value={event.resourceOid}
                        label={t('auditDetailResourceOid')}
                      />
                    }
                  />
                  <DetailRow
                    label={t('auditDetailResourceGlobalId')}
                    value={
                      event.resourceGlobalId ? (
                        <CopyableValue
                          value={event.resourceGlobalId}
                          label={t('auditDetailResourceGlobalId')}
                        />
                      ) : null
                    }
                  />
                  <DetailRow
                    label={t('auditDetailSubjectOid')}
                    value={
                      event.subjectOid ? (
                        <CopyableValue
                          value={event.subjectOid}
                          label={t('auditDetailSubjectOid')}
                        />
                      ) : null
                    }
                  />
                  <DetailRow
                    label={t('auditDetailSubjectGlobalId')}
                    value={
                      event.subjectGlobalId ? (
                        <CopyableValue
                          value={event.subjectGlobalId}
                          label={t('auditDetailSubjectGlobalId')}
                        />
                      ) : null
                    }
                  />
                </dl>
              </section>

              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t('auditDetailSectionCorrelation')}
                </h3>
                <dl className="divide-y divide-border/60 rounded-lg border border-border px-3.5">
                  <DetailRow
                    label={t('auditDetailRequestId')}
                    value={
                      event.requestId ? (
                        <CopyableValue
                          value={event.requestId}
                          label={t('auditDetailRequestId')}
                        />
                      ) : null
                    }
                    filterAction={
                      event.requestId
                        ? {
                            label: t('auditFilterByRequestId'),
                            onClick: () => onAppendFilter('requestId', event.requestId!),
                          }
                        : undefined
                    }
                  />
                  <DetailRow
                    label={t('auditDetailTraceId')}
                    value={
                      event.traceId ? (
                        <CopyableValue value={event.traceId} label={t('auditDetailTraceId')} />
                      ) : null
                    }
                    filterAction={
                      event.traceId
                        ? {
                            label: t('auditFilterByTraceId'),
                            onClick: () => onAppendFilter('traceId', event.traceId!),
                          }
                        : undefined
                    }
                  />
                </dl>
              </section>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
