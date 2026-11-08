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
import {
  versionConflict,
  type MutationFeedbackState,
} from '#/modules/user-management/users/lib/user-errors'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator } from '#/lib/i18n'

export function MutationFeedback({
  feedback,
  onReload,
  reloadPending = false,
}: {
  feedback: MutationFeedbackState
  onReload?: () => void
  reloadPending?: boolean
}) {
  const t = useTranslator()
  const conflict = versionConflict(feedback.errors)
  const hasIssue = feedback.errors.length > 0 || Boolean(feedback.failure)

  if (feedback.stepUp) {
    return (
      <StepUpPanel
        stepUp={feedback.stepUp}
        description={t('usersStepUpDescription')}
        note={t('usersStepUpNote')}
      />
    )
  }

  if (conflict.conflict) {
    return (
      <Alert variant="default" className="text-warning">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>{t('usersConflictTitle')}</AlertTitle>
        <AlertDescription>{t('usersConflictDescription')}</AlertDescription>
        <p className="mt-2 text-xs text-muted-foreground">
          {conflict.currentVersion
            ? t('usersConflictCurrentVersion', {
                version: conflict.currentVersion,
              })
            : t('usersConflictUnknownVersion')}
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
                <Spinner aria-label={t('usersReloading')} />
              ) : null}
              {t('usersReloadUser')}
            </Button>
          </div>
        ) : null}
      </Alert>
    )
  }

  if (!hasIssue) return null
  const hasFieldErrors = feedback.errors.some(
    (issue) => issue.fields.length > 0,
  )

  return (
    <Alert variant="destructive">
      <CircleAlert aria-hidden="true" />
      <AlertTitle>
        {hasFieldErrors
          ? t('fieldErrorsTitle')
          : t(failureTitleKey(feedback.failure, feedback.forbidden))}
      </AlertTitle>
      <AlertDescription>
        {hasFieldErrors
          ? t('usersMutationFailedDescription')
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

export interface UserNotice {
  kind: 'success' | 'warning'
  title: string
  description?: string
  requestId?: string
  traceId?: string
  issues?: ReadonlyArray<GraphQLIssue>
}

export function UserNoticeAlert({
  notice,
  onDismiss,
}: {
  notice: UserNotice
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
