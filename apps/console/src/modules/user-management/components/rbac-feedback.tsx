import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Spinner } from '@identity/ui/components/spinner'
import { CircleAlert, CircleCheck, TriangleAlert } from 'lucide-react'

import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  hasFieldErrors,
  rbacConflict,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'

export function RbacMutationFeedback({
  feedback,
  onReload,
  reloadPending = false,
  conflictTitleKey = 'rbacConflictTitle',
  conflictDescriptionKey = 'rbacConflictDescription',
}: {
  feedback: RbacFeedbackState
  onReload?: () => void
  reloadPending?: boolean
  conflictTitleKey?: MessageKey
  conflictDescriptionKey?: MessageKey
}) {
  const t = useTranslator()
  const conflict = rbacConflict(feedback.errors)

  if (feedback.stepUp) {
    return (
      <StepUpPanel
        stepUp={feedback.stepUp}
        description={t('rbacStepUpDescription')}
        note={t('rbacStepUpNote')}
      />
    )
  }

  if (conflict.conflict) {
    return (
      <Alert variant="default" className="text-warning">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>{t(conflictTitleKey)}</AlertTitle>
        <AlertDescription>{t(conflictDescriptionKey)}</AlertDescription>
        <p className="mt-2 text-xs text-muted-foreground">
          {conflict.currentVersion
            ? t('rbacConflictCurrentVersion', {
                version: conflict.currentVersion,
              })
            : t('rbacConflictUnknownVersion')}
        </p>
        <RequestCorrelation
          requestId={feedback.requestId}
          traceId={feedback.traceId}
        />
        <ErrorDetails issues={feedback.errors} />
        {onReload ? (
          <div className="mt-3">
            <Button
              size="sm"
              variant="secondary"
              disabled={reloadPending}
              onClick={onReload}
            >
              {reloadPending ? (
                <Spinner aria-label={t('rbacReloading')} />
              ) : null}
              {t('rbacReload')}
            </Button>
          </div>
        ) : null}
      </Alert>
    )
  }

  if (feedback.errors.length === 0 && !feedback.failure) return null

  const fields = hasFieldErrors(feedback.errors)
  return (
    <Alert variant="destructive">
      <CircleAlert aria-hidden="true" />
      <AlertTitle>
        {fields
          ? t('fieldErrorsTitle')
          : t(failureTitleKey(feedback.failure, feedback.forbidden))}
      </AlertTitle>
      <AlertDescription>
        {fields
          ? t('rbacMutationFieldDescription')
          : t(failureDescriptionKey(feedback.failure, feedback.forbidden))}
      </AlertDescription>
      <RequestCorrelation
        requestId={feedback.requestId}
        traceId={feedback.traceId}
      />
      <ErrorDetails issues={feedback.errors} />
    </Alert>
  )
}

export interface RbacNotice {
  kind: 'success' | 'warning'
  title: string
  description?: string
  requestId?: string
  traceId?: string
  issues?: ReadonlyArray<GraphQLIssue>
}

export function RbacNoticeAlert({
  notice,
  onDismiss,
}: {
  notice: RbacNotice
  onDismiss?: () => void
}) {
  const t = useTranslator()
  const warning = notice.kind === 'warning'

  return (
    <Alert
      variant="default"
      className={warning ? 'text-warning' : 'text-success'}
    >
      {warning ? (
        <TriangleAlert aria-hidden="true" />
      ) : (
        <CircleCheck aria-hidden="true" />
      )}
      <AlertTitle>{notice.title}</AlertTitle>
      {notice.description ? (
        <AlertDescription>{notice.description}</AlertDescription>
      ) : null}
      {warning ? (
        <RequestCorrelation
          requestId={notice.requestId}
          traceId={notice.traceId}
        />
      ) : null}
      <ErrorDetails issues={notice.issues} />
      {onDismiss ? (
        <div className="mt-3">
          <Button size="sm" variant="ghost" onClick={onDismiss}>
            {t('dismiss')}
          </Button>
        </div>
      ) : null}
    </Alert>
  )
}
