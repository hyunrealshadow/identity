import { Alert, Button, Spinner } from '@heroui/react'

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
      <Alert status="warning">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t(conflictTitleKey)}</Alert.Title>
          <Alert.Description>{t(conflictDescriptionKey)}</Alert.Description>
          <p className="mt-2 text-xs text-muted">
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
                isDisabled={reloadPending}
                onPress={onReload}
              >
                {reloadPending ? (
                  <Spinner size="sm" aria-label={t('rbacReloading')} />
                ) : null}
                {t('rbacReload')}
              </Button>
            </div>
          ) : null}
        </Alert.Content>
      </Alert>
    )
  }

  if (feedback.errors.length === 0 && !feedback.failure) return null

  const fields = hasFieldErrors(feedback.errors)
  return (
    <Alert status="danger">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>
          {fields
            ? t('fieldErrorsTitle')
            : t(failureTitleKey(feedback.failure, feedback.forbidden))}
        </Alert.Title>
        <Alert.Description>
          {fields
            ? t('rbacMutationFieldDescription')
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
  return (
    <Alert status={notice.kind}>
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{notice.title}</Alert.Title>
        {notice.description ? (
          <Alert.Description>{notice.description}</Alert.Description>
        ) : null}
        {notice.kind === 'warning' ? (
          <RequestCorrelation
            requestId={notice.requestId}
            traceId={notice.traceId}
          />
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
