import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@identity/ui/components/sheet'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Link } from '@tanstack/react-router'
import {
  AppWindow,
  ArrowRight,
  ChevronDown,
  Filter,
  Server,
  Shapes,
  ShieldQuestion,
  UserRound,
  type LucideIcon,
} from 'lucide-react'
import { useRef, type ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { CopyableValue } from '#/components/copy-button'
import type {
  AuditActorKind,
  AuditEventDetailQueryQuery,
  AuditEventFieldsFragment,
  AuditTargetKind,
} from '#/generated/graphql'
import { formatPreciseDateTime } from '#/lib/format'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { auditQueryValue } from '../lib/audit-catalog'
import {
  AUDIT_ACTOR_KIND_LABELS,
  AUDIT_AUTH_METHOD_LABELS,
  AUDIT_CATEGORY_LABELS,
  AUDIT_FIELD_LABELS,
  AUDIT_TARGET_KIND_LABELS,
} from '../lib/audit-labels'
import { auditActorName, auditChangeValueText, auditSentenceText } from '../lib/audit-presentation'
import { AuditEventSentence, AuditOutcomeBadge } from './audit-event-parts'

type LoadedDetail = NonNullable<AuditEventDetailQueryQuery['auditEvent']>

/** A listed event, completed by the detail query once it loads. */
export type AuditEventDetail = AuditEventFieldsFragment &
  Partial<Pick<LoadedDetail, 'client' | 'device'>>

export interface AuditEventDetailSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  event: AuditEventDetail | null | undefined
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

type Translate = ReturnType<typeof useTranslator>

const ACTOR_ICONS: Record<AuditActorKind, LucideIcon> = {
  USER: UserRound,
  CLIENT: AppWindow,
  SYSTEM: Server,
  ANONYMOUS: ShieldQuestion,
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-medium text-muted-foreground">{title}</h3>
      <dl className="space-y-3">{children}</dl>
    </section>
  )
}

function Field({
  label,
  children,
  centered = false,
}: {
  label: string
  children: ReactNode
  /** Centre the label on a value that starts with an icon, which has no text baseline. */
  centered?: boolean
}) {
  return (
    <div
      className={`grid grid-cols-[6rem_minmax(0,1fr)] gap-x-4 ${centered ? 'items-center' : 'items-baseline'}`}
    >
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm text-foreground">{children}</dd>
    </div>
  )
}

/** A person, application, or system named by the event. */
function Party({
  icon: Icon,
  name,
  detail,
  link,
}: {
  icon: LucideIcon
  name: string
  detail?: string | null
  link?: ReactNode
}) {
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-muted">
        <Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />
      </span>
      <div className="min-w-0">
        <div className="truncate font-medium">{link ?? name}</div>
        {detail ? <div className="truncate text-xs text-muted-foreground">{detail}</div> : null}
      </div>
    </div>
  )
}

const linkClass = 'text-link'

function targetLink(kind: AuditTargetKind, id: string, name: string): ReactNode {
  switch (kind) {
    case 'USER':
      return (
        <Link to="/users/$userId" params={{ userId: id }} className={linkClass}>
          {name}
        </Link>
      )
    case 'CLIENT':
      return (
        <Link to="/clients/$clientId" params={{ clientId: id }} className={linkClass}>
          {name}
        </Link>
      )
    case 'ROLE':
      return (
        <Link to="/roles/$roleId" params={{ roleId: id }} className={linkClass}>
          {name}
        </Link>
      )
    case 'GROUP':
      return (
        <Link to="/groups/$groupId" params={{ groupId: id }} className={linkClass}>
          {name}
        </Link>
      )
    case 'RESOURCE':
      return (
        <Link to="/resources/$resourceId" params={{ resourceId: id }} className={linkClass}>
          {name}
        </Link>
      )
    default:
      return null
  }
}

function ActorParty({ event, locale, t }: { event: AuditEventDetail; locale: string; t: Translate }) {
  const { actor } = event
  const kind = t(AUDIT_ACTOR_KIND_LABELS[actor.kind])
  const name = auditActorName(event, locale, t)
  if (actor.user) {
    return (
      <Party
        icon={UserRound}
        name={name}
        detail={actor.user.email}
        link={
          <Link to="/users/$userId" params={{ userId: actor.user.id }} className={linkClass}>
            {name}
          </Link>
        }
      />
    )
  }
  if (actor.client) {
    return (
      <Party
        icon={AppWindow}
        name={name}
        detail={kind}
        link={
          <Link to="/clients/$clientId" params={{ clientId: actor.client.id }} className={linkClass}>
            {name}
          </Link>
        }
      />
    )
  }
  // A deleted account or a reader without access keeps the recorded name.
  return (
    <Party
      icon={ACTOR_ICONS[actor.kind]}
      name={name}
      detail={actor.label ? kind : actor.kind === 'ANONYMOUS' ? t('auditDetailAnonymousHint') : null}
    />
  )
}

function ChangeValue({ change, t }: { change: AuditEventDetail['changes'][number]; t: Translate }) {
  const empty = t('auditChangeEmpty')
  if (change.kind === 'REDACTED') {
    return <span className="text-muted-foreground">{t('auditChangeRedacted')}</span>
  }
  if (change.kind === 'SET') {
    return (
      <div className="flex flex-wrap gap-1.5">
        {change.added.map((item, index) => (
          <Badge key={`added-${index}`} variant="secondary">
            <span aria-label={t('auditChangeAdded')}>+</span>
            {auditChangeValueText(item, empty)}
          </Badge>
        ))}
        {change.removed.map((item, index) => (
          <Badge key={`removed-${index}`} variant="outline" className="text-muted-foreground">
            <span aria-label={t('auditChangeRemoved')}>−</span>
            <span className="line-through">{auditChangeValueText(item, empty)}</span>
          </Badge>
        ))}
      </div>
    )
  }
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="text-muted-foreground line-through decoration-muted-foreground/60">
        <span className="sr-only">{t('auditChangeBefore')} </span>
        {auditChangeValueText(change.oldValue, empty)}
      </span>
      <ArrowRight className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span>
        <span className="sr-only">{t('auditChangeAfter')} </span>
        {auditChangeValueText(change.newValue, empty)}
      </span>
    </div>
  )
}

function deviceText(device: AuditEventDetail['device']): string | null {
  if (!device) return null
  const browser = [device.browser, device.browserVersion?.split('.')[0]].filter(Boolean).join(' ')
  const os = [device.os, device.osVersion].filter(Boolean).join(' ')
  return [browser, os].filter(Boolean).join(' - ') || null
}

function FilterSimilarMenu({
  event,
  t,
  onAppendFilter,
}: {
  event: AuditEventDetail
  t: Translate
  onAppendFilter: (field: string, value: string) => void
}) {
  const items: Array<{ label: MessageKey; field: string; value: string | null | undefined }> = [
    { label: 'auditFilterByAction', field: 'action', value: auditQueryValue(event.action) },
    { label: 'auditFilterByActor', field: 'actor', value: event.actor.oid },
    { label: 'auditFilterByTarget', field: 'target', value: event.target?.oid },
    { label: 'auditFilterByIpAddress', field: 'ipAddress', value: event.ipAddress },
    { label: 'auditFilterByRequestId', field: 'requestId', value: event.requestId },
  ]
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button type="button" variant="outline" size="sm" />}>
        <Filter className="size-3.5" aria-hidden="true" />
        {t('auditDetailFilterSimilar')}
        <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-48">
        {items.map((item) =>
          item.value ? (
            <DropdownMenuItem
              key={item.field}
              onClick={() => onAppendFilter(item.field, item.value as string)}
            >
              {t(item.label)}
            </DropdownMenuItem>
          ) : null,
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function DetailBody({ event, t }: { event: AuditEventDetail; t: Translate }) {
  const { locale } = useLocale()
  const target = event.target
  const targetName = target
    ? (target.label ?? `${t(AUDIT_TARGET_KIND_LABELS[target.kind])} ${target.oid.slice(0, 8)}`)
    : null
  const clientName = event.client
    ? (resolveLocalizedText(event.client.names, locale) ?? event.client.name)
    : null
  const device = deviceText(event.device)

  return (
    <>
      <Section title={t('auditDetailSectionParties')}>
        <Field label={t('auditDetailSectionWho')} centered>
          <ActorParty event={event} locale={locale} t={t} />
        </Field>
        {/* A sign-in or self-service change acts on the actor itself. */}
        {target && targetName && target.oid !== event.actor.oid ? (
          <Field label={t('auditDetailSectionWhat')} centered>
            <Party
              icon={target.kind === 'CLIENT' ? AppWindow : target.kind === 'USER' ? UserRound : Shapes}
              name={targetName}
              detail={t(AUDIT_TARGET_KIND_LABELS[target.kind])}
              link={target.id ? targetLink(target.kind, target.id, targetName) : null}
            />
          </Field>
        ) : null}
        {/* A client already named as the actor or the object is not repeated. */}
        {event.clientId && event.clientId !== event.actor.id && event.clientId !== target?.id ? (
          <Field label={t('auditDetailClient')} centered>
            {event.client === undefined ? (
              // Still loading with the detail query.
              <Skeleton className="h-6 w-40" />
            ) : (
            <Party
              icon={AppWindow}
              name={clientName ?? t('auditDetailClientUnavailable')}
              link={
                clientName && event.client ? (
                  <Link
                    to="/clients/$clientId"
                    params={{ clientId: event.client.id }}
                    className={linkClass}
                  >
                    {clientName}
                  </Link>
                ) : null
              }
            />
            )}
          </Field>
        ) : null}
      </Section>

      {event.changes.length > 0 ? (
        <Section title={t('auditDetailSectionChanges')}>
          {event.changes.map((change) => (
            <Field key={change.field} label={t(AUDIT_FIELD_LABELS[change.field])}>
              <ChangeValue change={change} t={t} />
            </Field>
          ))}
        </Section>
      ) : null}

      {event.ipAddress || event.userAgent || event.authMethods.length > 0 ? (
        <Section title={t('auditDetailSectionContext')}>
          {event.authMethods.length > 0 ? (
            <Field label={t('auditDetailAuthMethods')}>
              <div className="flex flex-wrap gap-1.5">
                {event.authMethods.map((method) => (
                  <Badge key={method} variant="secondary">
                    {t(AUDIT_AUTH_METHOD_LABELS[method])}
                  </Badge>
                ))}
              </div>
            </Field>
          ) : null}
          {event.ipAddress ? (
            <Field label={t('auditDetailIpAddress')}>
              <CopyableValue value={event.ipAddress} label={t('auditDetailIpAddress')} />
            </Field>
          ) : null}
          {event.userAgent ? (
            <Field label={t('auditDetailDevice')}>
              <span title={event.userAgent}>{device ?? t('auditDetailDeviceUnknown')}</span>
            </Field>
          ) : null}
        </Section>
      ) : null}

      <Section title={t('auditDetailSectionDiagnostics')}>
        <Field label={t('auditDetailEventId')}>
          <CopyableValue value={event.id} label={t('auditDetailEventId')} />
        </Field>
        {event.requestId ? (
          <Field label={t('auditDetailRequestId')}>
            <CopyableValue value={event.requestId} label={t('auditDetailRequestId')} />
          </Field>
        ) : null}
        {event.traceId ? (
          <Field label={t('auditDetailTraceId')}>
            <CopyableValue value={event.traceId} label={t('auditDetailTraceId')} />
          </Field>
        ) : null}
        {event.userAgent ? (
          <Field label={t('auditDetailUserAgent')}>
            <CopyableValue value={event.userAgent} label={t('auditDetailUserAgent')} />
          </Field>
        ) : null}
      </Section>
    </>
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
  // Focus the content, not the first control, so opening does not look like
  // the filter menu was chosen.
  const bodyRef = useRef<HTMLDivElement>(null)

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        closeLabel={t('auditDetailClose')}
        className="w-full gap-0 sm:max-w-lg"
        initialFocus={bodyRef}
      >
        <SheetHeader className="gap-3 border-b border-border px-6 pt-6 pb-5">
          {event ? (
            <div className="flex flex-wrap items-center gap-2 pr-8 text-xs text-muted-foreground">
              <span>{t(AUDIT_CATEGORY_LABELS[event.category])}</span>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono">
                {auditQueryValue(event.action)}
              </code>
            </div>
          ) : null}
          <SheetTitle className="pr-8 text-base leading-snug font-normal text-muted-foreground">
            {event ? (
              <>
                <span className="sr-only">{auditSentenceText(event, locale, t)}</span>
                <span aria-hidden="true">
                  <AuditEventSentence event={event} locale={locale} />
                </span>
              </>
            ) : (
              t('auditDetailTitle')
            )}
          </SheetTitle>
          {event ? (
            <SheetDescription className="flex flex-wrap items-center gap-2">
              <AuditOutcomeBadge event={event} />
              <time dateTime={event.occurredAt}>
                {formatPreciseDateTime(event.occurredAt, locale, timeZone)}
              </time>
            </SheetDescription>
          ) : (
            <SheetDescription className="sr-only">{t('auditDescription')}</SheetDescription>
          )}
          {event ? (
            <div>
              <FilterSimilarMenu event={event} t={t} onAppendFilter={onAppendFilter} />
            </div>
          ) : null}
        </SheetHeader>

        <div
          ref={bodyRef}
          tabIndex={-1}
          className="flex-1 space-y-6 overflow-y-auto px-6 py-5 outline-none"
        >
          {loading ? (
            <div className="space-y-4" aria-busy="true">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-9 w-full" />
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
            <DetailBody event={event} t={t} />
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
