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
import { auditQueryValue } from '../lib/audit-catalog'
import {
  AUDIT_ACTOR_KIND_LABELS,
  AUDIT_AUTH_METHOD_LABELS,
  AUDIT_CATEGORY_LABELS,
  AUDIT_FAILURE_REASON_LABELS,
  AUDIT_FIELD_LABELS,
  AUDIT_OUTCOME_LABELS,
  AUDIT_TARGET_KIND_LABELS,
} from '../lib/audit-labels'
import {
  auditActionLabel,
  auditActorName,
  auditChangeValueText,
  auditTargetName,
} from '../lib/audit-presentation'

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

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </h3>
      <dl className="divide-y divide-border/60 rounded-lg border border-border px-3.5">
        {children}
      </dl>
    </section>
  )
}

function ChangeList({ event }: { event: AuditEventFieldsFragment }) {
  const t = useTranslator()
  const empty = t('auditChangeEmpty')
  return (
    <Section title={t('auditDetailSectionChanges')}>
      {event.changes.map((change) => (
        <DetailRow
          key={change.field}
          label={t(AUDIT_FIELD_LABELS[change.field])}
          value={
            change.kind === 'REDACTED' ? (
              <span className="text-muted-foreground">{t('auditChangeRedacted')}</span>
            ) : change.kind === 'SET' ? (
              <div className="space-y-1">
                {change.added.length > 0 ? (
                  <div>
                    <span className="mr-2 text-xs text-muted-foreground">{t('auditChangeAdded')}</span>
                    {change.added.map((item) => auditChangeValueText(item, empty)).join(', ')}
                  </div>
                ) : null}
                {change.removed.length > 0 ? (
                  <div>
                    <span className="mr-2 text-xs text-muted-foreground">
                      {t('auditChangeRemoved')}
                    </span>
                    <span className="line-through decoration-muted-foreground/60">
                      {change.removed.map((item) => auditChangeValueText(item, empty)).join(', ')}
                    </span>
                  </div>
                ) : null}
              </div>
            ) : (
              <div className="space-y-1">
                <div>
                  <span className="mr-2 text-xs text-muted-foreground">{t('auditChangeBefore')}</span>
                  <span className="line-through decoration-muted-foreground/60">
                    {auditChangeValueText(change.oldValue, empty)}
                  </span>
                </div>
                <div>
                  <span className="mr-2 text-xs text-muted-foreground">{t('auditChangeAfter')}</span>
                  {auditChangeValueText(change.newValue, empty)}
                </div>
              </div>
            )
          }
        />
      ))}
    </Section>
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

  const actorAccount = (() => {
    if (!event) return null
    const { user, client } = event.actor
    if (user) {
      return (
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to="/users/$userId"
            params={{ userId: user.id }}
            className="font-medium underline-offset-4 hover:underline"
          >
            {user.nickname?.trim() || user.username}
          </Link>
          <span className="text-xs text-muted-foreground">{user.email}</span>
        </div>
      )
    }
    if (client) {
      return (
        <Link
          to="/clients/$clientId"
          params={{ clientId: client.id }}
          className="font-medium underline-offset-4 hover:underline"
        >
          {auditActorName(event, locale, t)}
        </Link>
      )
    }
    return null
  })()

  const copyable = (value: string | null | undefined, label: string) =>
    value ? <CopyableValue value={value} label={label} /> : null
  const filter = (label: string, field: string, value: string | null | undefined) =>
    value ? { label, onClick: () => onAppendFilter(field, value) } : undefined

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        closeLabel={t('auditDetailClose')}
        className="w-full overflow-y-auto sm:max-w-xl"
      >
        <SheetHeader className="border-b border-border pb-4">
          <SheetTitle>
            {event
              ? [auditActorName(event, locale, t), auditActionLabel(event, t), auditTargetName(event, t)]
                  .filter(Boolean)
                  .join(' ')
              : t('auditDetailTitle')}
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
              <Section title={t('auditDetailTitle')}>
                <DetailRow
                  label={t('auditDetailAction')}
                  value={auditActionLabel(event, t)}
                  filterAction={filter(
                    t('auditFilterByAction'),
                    'action',
                    auditQueryValue(event.action),
                  )}
                />
                <DetailRow
                  label={t('auditDetailCategory')}
                  value={t(AUDIT_CATEGORY_LABELS[event.category])}
                />
                <DetailRow
                  label={t('auditDetailOutcome')}
                  value={
                    <span className={event.outcome === 'FAILURE' ? 'text-destructive' : undefined}>
                      {t(AUDIT_OUTCOME_LABELS[event.outcome])}
                    </span>
                  }
                />
                <DetailRow
                  label={t('auditDetailFailureReason')}
                  value={
                    event.failureReason ? t(AUDIT_FAILURE_REASON_LABELS[event.failureReason]) : null
                  }
                />
                <DetailRow
                  label={t('auditDetailAuthMethods')}
                  value={
                    event.authMethods.length > 0
                      ? event.authMethods.map((method) => t(AUDIT_AUTH_METHOD_LABELS[method])).join(' + ')
                      : null
                  }
                />
                <DetailRow
                  label={t('auditDetailOccurredAt')}
                  value={formatDateTime(event.occurredAt, locale, timeZone)}
                />
                <DetailRow
                  label={t('auditDetailEventId')}
                  value={copyable(event.id, t('auditDetailEventId'))}
                />
              </Section>

              <Section title={t('auditDetailSectionWho')}>
                <DetailRow
                  label={t('auditDetailKind')}
                  value={t(AUDIT_ACTOR_KIND_LABELS[event.actor.kind])}
                />
                <DetailRow label={t('auditDetailName')} value={event.actor.label} />
                <DetailRow label={t('auditDetailAccount')} value={actorAccount} />
                <DetailRow
                  label={t('auditDetailOid')}
                  value={copyable(event.actor.oid, t('auditDetailOid'))}
                  filterAction={filter(t('auditFilterByActor'), 'actor', event.actor.oid)}
                />
              </Section>

              {event.target ? (
                <Section title={t('auditDetailSectionWhat')}>
                  <DetailRow
                    label={t('auditDetailKind')}
                    value={t(AUDIT_TARGET_KIND_LABELS[event.target.kind])}
                  />
                  <DetailRow label={t('auditDetailName')} value={event.target.label} />
                  <DetailRow
                    label={t('auditDetailOid')}
                    value={copyable(event.target.oid, t('auditDetailOid'))}
                    filterAction={filter(t('auditFilterByTarget'), 'target', event.target.oid)}
                  />
                </Section>
              ) : null}

              {event.changes.length > 0 ? <ChangeList event={event} /> : null}

              <Section title={t('auditDetailSectionContext')}>
                <DetailRow
                  label={t('auditDetailClient')}
                  value={copyable(event.clientId, t('auditDetailClient'))}
                />
                <DetailRow
                  label={t('auditDetailIpAddress')}
                  value={copyable(event.ipAddress, t('auditDetailIpAddress'))}
                  filterAction={filter(t('auditFilterByIpAddress'), 'ipAddress', event.ipAddress)}
                />
                <DetailRow label={t('auditDetailUserAgent')} value={event.userAgent} />
                <DetailRow
                  label={t('auditDetailRequestId')}
                  value={copyable(event.requestId, t('auditDetailRequestId'))}
                  filterAction={filter(t('auditFilterByRequestId'), 'requestId', event.requestId)}
                />
                <DetailRow
                  label={t('auditDetailTraceId')}
                  value={copyable(event.traceId, t('auditDetailTraceId'))}
                  filterAction={filter(t('auditFilterByTraceId'), 'traceId', event.traceId)}
                />
              </Section>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
