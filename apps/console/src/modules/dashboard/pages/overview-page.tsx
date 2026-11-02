import { Button, Spinner } from '@heroui/react'
import { RefreshCw } from 'lucide-react'
import { useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
import { PageHeader } from '#/components/page-header'
import { StepUpPanel } from '#/components/step-up-panel'
import { dashboardScope } from '#/modules/dashboard/lib/dashboard-scope'
import { useInstanceDashboard } from '#/modules/dashboard/hooks/instance-dashboard'
import {
  DashboardLoading,
  InstanceDashboardView,
  NoManagementAccess,
} from '#/modules/dashboard/components/instance-dashboard-view'
import { exactUtc, formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

function LastUpdated({
  generatedAt,
  refreshing,
  onRefresh,
}: {
  generatedAt: string | null | undefined
  refreshing: boolean
  onRefresh: () => void
}) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const exact = exactUtc(generatedAt)

  return (
    <div className="flex flex-wrap items-center justify-end gap-3">
      {exact ? (
        <p className="text-xs text-muted" aria-live="polite">
          <span>{t('dashboardLastUpdated')}</span>{' '}
          <time dateTime={exact}>
            {formatDateTime(generatedAt, locale, timeZone)}
          </time>
        </p>
      ) : null}
      <Button
        size="sm"
        variant="secondary"
        aria-label={t('dashboardRefreshLabel')}
        isDisabled={refreshing}
        onPress={onRefresh}
      >
        {refreshing ? (
          <Spinner size="sm" aria-label={t('dashboardRefreshing')} />
        ) : (
          <RefreshCw className="size-4" aria-hidden="true" />
        )}
        <span>{t('refresh')}</span>
      </Button>
    </div>
  )
}

export function OverviewPage() {
  const t = useTranslator()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions ?? null
  const scope = useMemo(() => dashboardScope(permissions), [permissions])
  const dashboard = useInstanceDashboard(permissions)

  const headerActions =
    scope.hasAny && dashboard.status === 'ready' && dashboard.data ? (
      <LastUpdated
        generatedAt={dashboard.data.generatedAt}
        refreshing={dashboard.refreshing}
        onRefresh={() => void dashboard.refresh()}
      />
    ) : undefined

  const header = (
    <PageHeader
      title={t('overviewTitle')}
      description={t('overviewDescription')}
      actions={headerActions}
    />
  )

  if (workspace.status === 'idle' || workspace.status === 'loading') {
    return (
      <>
        {header}
        <AsyncState kind="loading" title={t('loading')} />
      </>
    )
  }

  if (workspace.status === 'error') {
    return (
      <>
        {header}
        {workspace.stepUp ? (
          <StepUpPanel
            stepUp={workspace.stepUp}
            hideDetails
            description={t('dashboardStepUpDescription')}
            note={t('dashboardStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={workspace.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(workspace.failure, workspace.forbidden))}
            description={t(
              failureDescriptionKey(workspace.failure, workspace.forbidden),
            )}
            requestId={workspace.requestId}
            traceId={workspace.traceId}
            issues={workspace.errors}
            onRetry={() => void workspace.refresh()}
          />
        )}
      </>
    )
  }

  if (!permissions) {
    const failed = workspace.failure || workspace.forbidden
    return (
      <>
        {header}
        <AsyncState
          kind={
            workspace.forbidden ? 'forbidden' : failed ? 'error' : 'partial'
          }
          title={t(
            failed
              ? failureTitleKey(workspace.failure, workspace.forbidden)
              : 'partialTitle',
          )}
          description={t(
            failed
              ? failureDescriptionKey(workspace.failure, workspace.forbidden)
              : 'partialDescription',
          )}
          requestId={workspace.requestId}
          traceId={workspace.traceId}
          issues={workspace.errors}
          onRetry={() => void workspace.refresh()}
        />
      </>
    )
  }

  if (workspace.stepUp && !scope.hasAny) {
    return (
      <>
        {header}
        <StepUpPanel
          stepUp={workspace.stepUp}
          hideDetails
          description={t('dashboardStepUpDescription')}
          note={t('dashboardStepUpNote')}
        />
      </>
    )
  }

  if (!scope.hasAny) {
    return (
      <>
        {header}
        <NoManagementAccess />
      </>
    )
  }

  if (dashboard.status === 'error') {
    return (
      <>
        {header}
        <AsyncState
          kind={dashboard.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(dashboard.failure, dashboard.forbidden))}
          description={t(
            failureDescriptionKey(dashboard.failure, dashboard.forbidden),
          )}
          requestId={dashboard.requestId}
          traceId={dashboard.traceId}
          issues={dashboard.errors}
          onRetry={() => void dashboard.refresh()}
        />
      </>
    )
  }

  if (!dashboard.data) {
    return (
      <>
        {header}
        <DashboardLoading />
      </>
    )
  }

  return (
    <>
      {header}
      <InstanceDashboardView
        data={dashboard.data}
        scope={dashboard.scope}
        issues={dashboard.errors}
        partial={dashboard.partial}
        onRefresh={() => void dashboard.refresh()}
      />
    </>
  )
}
