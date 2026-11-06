import { Button, Card, Skeleton } from '@heroui/react'
import {
  AppWindow,
  Boxes,
  Lock,
  Monitor,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { useId } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import type { DashboardScope } from '#/modules/dashboard/lib/dashboard-scope'
import type {
  InstanceDashboardUsers,
  InstanceOverview,
  RegistrationBucket,
} from '#/modules/dashboard/hooks/instance-dashboard'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import {
  formatNumber,
  formatCalendarDate,
  formatCalendarDay,
} from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'

function issuesFor(
  issues: ReadonlyArray<GraphQLIssue>,
  section: string,
): ReadonlyArray<GraphQLIssue> {
  return issues.filter((issue) => issue.path?.includes(section))
}

function ModuleNoAccess() {
  const t = useTranslator()
  return (
    <div className="mt-3">
      <p className="flex items-center gap-1.5 text-sm font-medium text-muted">
        <Lock className="size-3.5 shrink-0" aria-hidden="true" />
        {t('dashboardModuleNoAccess')}
      </p>
      <p className="mt-1 text-xs leading-5 text-muted">
        {t('dashboardModuleNoAccessDescription')}
      </p>
    </div>
  )
}

function ModuleUnavailable({
  onRetry,
  issues,
}: {
  onRetry: () => void
  issues: ReadonlyArray<GraphQLIssue>
}) {
  const t = useTranslator()
  return (
    <div className="mt-3">
      <p className="text-sm font-medium text-muted">{t('dashboardModuleUnavailable')}</p>
      <p className="mt-1 text-xs leading-5 text-muted">
        {t('dashboardModuleUnavailableDescription')}
      </p>
      <ErrorDetails issues={issues.length > 0 ? issues : undefined} />
      <Button size="sm" variant="ghost" className="mt-2 px-0" onPress={onRetry}>
        {t('retry')}
      </Button>
    </div>
  )
}

function KpiCard({
  title,
  icon: Icon,
  included,
  value,
  onRetry,
  issues,
}: {
  title: string
  icon: LucideIcon
  included: boolean
  value: number | null | undefined
  onRetry: () => void
  issues: ReadonlyArray<GraphQLIssue>
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const headingId = useId()
  const formatted = value === null || value === undefined ? undefined : formatNumber(value, locale)

  return (
    <Card className="console-card min-h-28 border border-border p-5">
      <Card.Content className="p-0">
        <section aria-labelledby={headingId}>
          <div className="flex items-start justify-between gap-3">
            <h2 id={headingId} className="text-sm font-medium text-muted">
              {title}
            </h2>
            <Icon className="size-6 shrink-0 text-muted" aria-hidden="true" />
          </div>
          {!included ? (
            <ModuleNoAccess />
          ) : formatted === undefined ? (
            <ModuleUnavailable onRetry={onRetry} issues={issues} />
          ) : (
            <p
              className="mt-3 text-[30px] font-semibold leading-none tracking-tight tabular-nums text-foreground"
              aria-label={t('dashboardKpiValue', { title, value: formatted })}
            >
              {formatted}
            </p>
          )}
        </section>
      </Card.Content>
    </Card>
  )
}

export function NewUsersChart({
  registrations,
}: {
  registrations: ReadonlyArray<RegistrationBucket>
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const total = registrations.reduce((sum, bucket) => sum + bucket.count, 0)
  const max = Math.max(...registrations.map((bucket) => bucket.count), 1)
  const title = t('dashboardNewUsersTitle')
  const barMaxHeight = 136

  return (
    <div className="mt-4 min-w-0">
      <div
        role="img"
        className="min-w-0"
        aria-label={t('dashboardChartLabel', {
          title,
          total: t('dashboardNewUsersTotal', { count: total }),
        })}
      >
        <div className="relative h-44 min-w-0" aria-hidden="true">
          <div className="pointer-events-none absolute inset-0 flex flex-col justify-between">
            {Array.from({ length: 5 }, (_, index) => (
              <span key={index} className="block border-t border-separator" />
            ))}
          </div>
          <div className="relative flex h-full min-w-0 items-end gap-0 sm:gap-2">
            {registrations.map((bucket) => {
              const height =
                bucket.count === 0
                  ? 0
                  : Math.max(6, Math.round((bucket.count / max) * barMaxHeight))
              return (
                <div
                  key={bucket.date}
                  className="flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                >
                  <span className="mb-1 text-[10px] tabular-nums text-muted">
                    {formatNumber(bucket.count, locale)}
                  </span>
                  {height > 0 ? (
                    <div
                      className="w-full max-w-6 rounded-t-[3px] bg-accent"
                      style={{ height }}
                      title={t('dashboardChartDay', {
                        date: formatCalendarDate(bucket.date, locale),
                        count: bucket.count,
                      })}
                    />
                  ) : null}
                </div>
              )
            })}
          </div>
        </div>
        <div className="mt-2 flex min-w-0 gap-0 sm:gap-2" aria-hidden="true">
          {registrations.map((bucket) => (
            <span
              key={bucket.date}
              className="min-w-0 flex-1 whitespace-normal break-words text-center text-[9px] leading-tight text-muted sm:text-[10px]"
            >
              {formatCalendarDay(bucket.date, locale)}
            </span>
          ))}
        </div>
      </div>
      <table className="sr-only">
        <caption>{t('dashboardChartCaption')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('dashboardChartDate')}</th>
            <th scope="col">{t('dashboardChartCount')}</th>
          </tr>
        </thead>
        <tbody>
          {registrations.map((bucket) => (
            <tr key={bucket.date}>
              <th scope="row">{formatCalendarDate(bucket.date, locale)}</th>
              <td>{formatNumber(bucket.count, locale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function NewUsersCard({
  users,
  included,
  onRetry,
  issues,
}: {
  users: InstanceDashboardUsers | null | undefined
  included: boolean
  onRetry: () => void
  issues: ReadonlyArray<GraphQLIssue>
}) {
  const t = useTranslator()
  const sectionIssues = issuesFor(issues, 'users')

  return (
    <Card className="console-card h-full min-w-0 gap-0 border border-border p-5">
      <Card.Header className="p-0">
        <Card.Title className="text-base font-semibold">
          {t('dashboardNewUsersTitle')}
        </Card.Title>
        <Card.Description className="mt-1 text-sm text-muted">
          {t('dashboardNewUsersDescription')}
        </Card.Description>
      </Card.Header>
      <Card.Content className="min-w-0 p-0">
        {!included ? (
          <ModuleNoAccess />
        ) : !users ? (
          <ModuleUnavailable onRetry={onRetry} issues={sectionIssues} />
        ) : users.registrations.length === 0 ? (
          <p className="text-sm text-muted">{t('dashboardNewUsersNoData')}</p>
        ) : (
          <>
            <p className="text-sm text-muted">
              {t('dashboardNewUsersTotal', { count: users.createdLast7Days })}
            </p>
            {users.registrations.every((bucket) => bucket.count === 0) ? (
              <div className="mt-4 rounded-field border border-dashed border-border px-4 py-6">
                <p className="text-sm font-medium">{t('dashboardNewUsersEmpty')}</p>
                <p className="mt-1 text-xs leading-5 text-muted">
                  {t('dashboardNewUsersEmptyDescription')}
                </p>
              </div>
            ) : (
              <NewUsersChart registrations={users.registrations} />
            )}
          </>
        )}
      </Card.Content>
    </Card>
  )
}

export function NoManagementAccess() {
  const t = useTranslator()

  return (
    <Card className="console-card border border-border p-6 sm:p-8">
      <Card.Content className="p-0">
        <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
          <Lock className="size-5" aria-hidden="true" />
        </span>
        <h2 className="mt-4 text-lg font-semibold tracking-tight">
          {t('dashboardNoAccessTitle')}
        </h2>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
          {t('dashboardNoAccessDescription')}
        </p>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted">
          {t('dashboardNoAccessContact')}
        </p>
      </Card.Content>
    </Card>
  )
}

export function DashboardLoading() {
  const t = useTranslator()

  return (
    <div
      className="space-y-4"
      role="status"
      aria-live="polite"
      aria-label={t('dashboardLoading')}
    >
      <span className="sr-only">{t('dashboardLoading')}</span>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-28 w-full rounded-field" />
        ))}
      </div>
      <Skeleton className="h-72 w-full rounded-field" />
    </div>
  )
}

export function InstanceDashboardView({
  data,
  scope,
  issues,
  partial,
  onRefresh,
}: {
  data: InstanceOverview
  scope: DashboardScope
  issues: ReadonlyArray<GraphQLIssue>
  partial: boolean
  onRefresh: () => void
}) {
  const t = useTranslator()

  const users = data.users ?? null
  const clients = data.clients ?? null
  const sessions = data.sessions ?? null
  const resources = data.resources ?? null

  return (
    <div>
      {partial ? (
        <div className="mb-4">
          <AsyncState
            kind="partial"
            title={t('dashboardPartialTitle')}
            description={t('dashboardPartialDescription')}
            issues={issues}
            onRetry={onRefresh}
          />
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          title={t('dashboardUsersTitle')}
          icon={Users}
          included={scope.users}
          value={users?.total}
          onRetry={onRefresh}
          issues={issuesFor(issues, 'users')}
        />
        <KpiCard
          title={t('dashboardClientsTitle')}
          icon={AppWindow}
          included={scope.clients}
          value={clients?.total}
          onRetry={onRefresh}
          issues={issuesFor(issues, 'clients')}
        />
        <KpiCard
          title={t('dashboardSessionsTitle')}
          icon={Monitor}
          included={scope.sessions}
          value={sessions?.active}
          onRetry={onRefresh}
          issues={issuesFor(issues, 'sessions')}
        />
        <KpiCard
          title={t('dashboardResourcesTitle')}
          icon={Boxes}
          included={scope.resources}
          value={resources?.total}
          onRetry={onRefresh}
          issues={issuesFor(issues, 'resources')}
        />
      </div>

      <div className="mt-4 min-w-0">
        <NewUsersCard
          users={users}
          included={scope.users}
          onRetry={onRefresh}
          issues={issues}
        />
      </div>
    </div>
  )
}
