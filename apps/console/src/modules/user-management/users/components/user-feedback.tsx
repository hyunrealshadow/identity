import { Alert, Button, Spinner } from '@heroui/react'

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
      <Alert status="warning">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t('usersConflictTitle')}</Alert.Title>
          <Alert.Description>
            {t('usersConflictDescription')}
          </Alert.Description>
          <p className="mt-2 text-xs text-muted">
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
                isDisabled={reloadPending}
                onPress={onReload}
              >
                {reloadPending ? (
                  <Spinner size="sm" aria-label={t('usersReloading')} />
                ) : null}
                {t('usersReloadUser')}
              </Button>
            </div>
          ) : null}
        </Alert.Content>
      </Alert>
    )
  }

  if (!hasIssue) return null
  const hasFieldErrors = feedback.errors.some(
    (issue) => issue.fields.length > 0,
  )

  return (
    <Alert status="danger">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>
          {hasFieldErrors
            ? t('fieldErrorsTitle')
            : t(failureTitleKey(feedback.failure, feedback.forbidden))}
        </Alert.Title>
        <Alert.Description>
          {hasFieldErrors
            ? t('usersMutationFailedDescription')
            : t(failureDescriptionKey(feedback.failure, feedback.forbidden))}
        </Alert.Description>
        <RequestCorrelation
          requestId={feedback.requestId}
          traceId={feedback.traceId}
        />
        <ErrorDetails issues={feedback.errors} />
      </Alert.Content>
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

  return (
    <Alert status={notice.kind}>
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{notice.title}</Alert.Title>
        {notice.description ? (
          <Alert.Description>{notice.description}</Alert.Description>
        ) : null}
        {notice.kind === 'warning' ? (
          <RequestCorrelation requestId={notice.requestId} traceId={notice.traceId} />
        ) : null}
        <ErrorDetails issues={notice.issues} />
        {onDismiss ? (
          <div className="mt-3">
            <Button size="sm" variant="ghost" onPress={onDismiss}>
              {t('dismiss')}
            </Button>
          </div>
        ) : null}
      </Alert.Content>
    </Alert>
  )
}
