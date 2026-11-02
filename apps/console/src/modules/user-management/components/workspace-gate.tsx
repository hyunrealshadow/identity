import type { ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

/**
 * Renders the shared workspace read outcome before a management page decides
 * its own feature-level denial. It preserves partial data when permissions are
 * available and never substitutes a fake empty result.
 */
export function ConsoleWorkspaceGate({ children, loading }: { children: ReactNode; loading?: ReactNode }) {
  const t = useTranslator()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions ?? null

  if ((workspace.status === 'idle' || workspace.status === 'loading') && !permissions) {
    return <>{loading ?? <AsyncState kind="loading" title={t('loading')} />}</>
  }

  if (workspace.status === 'error' && !permissions) {
    return workspace.stepUp ? (
      <StepUpPanel
        stepUp={workspace.stepUp}
        hideDetails
        description={t('rbacStepUpDescription')}
        note={t('rbacStepUpNote')}
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
    )
  }

  if (!permissions) {
    return (
      <AsyncState
        kind={workspace.forbidden ? 'forbidden' : 'partial'}
        title={t(
          workspace.forbidden
            ? failureTitleKey(workspace.failure, true)
            : 'partialTitle',
        )}
        description={t(
          workspace.forbidden
            ? failureDescriptionKey(workspace.failure, true)
            : 'partialDescription',
        )}
        requestId={workspace.requestId}
        traceId={workspace.traceId}
        issues={workspace.errors}
        onRetry={() => void workspace.refresh()}
      />
    )
  }

  return <>{children}</>
}

export function RbacStepUp({
  description,
  note,
}: {
  description?: string
  note?: string
}) {
  const t = useTranslator()
  return (
    <StepUpPanel
      stepUp={{ source: 'graphql', acrValues: 'aal2' }}
      hideDetails
      description={description ?? t('rbacStepUpDescription')}
      note={note ?? t('rbacStepUpNote')}
    />
  )
}
