import { Alert, Button, EmptyState, Skeleton, Spinner } from '@heroui/react'
import type { ReactNode } from 'react'

import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useTranslator, type MessageKey } from '#/lib/i18n'

export type AsyncStateKind =
  | 'loading'
  | 'error'
  | 'unauthorized'
  | 'forbidden'
  | 'notFound'
  | 'empty'
  | 'partial'

const defaultTitles: Partial<Record<AsyncStateKind, MessageKey>> = {
  loading: 'loading',
  error: 'errorTitle',
  unauthorized: 'unauthorizedTitle',
  forbidden: 'forbiddenTitle',
  notFound: 'notFoundTitle',
  partial: 'partialTitle',
}

const defaultDescriptions: Partial<Record<AsyncStateKind, MessageKey>> = {
  error: 'errorDescriptionFallback',
  unauthorized: 'unauthorizedDescription',
  forbidden: 'forbiddenDescription',
  notFound: 'notFoundDescription',
  partial: 'partialDescription',
}

export function AsyncState({
  kind,
  title,
  description,
  requestId,
  traceId,
  issues,
  onRetry,
  action,
  compact = false,
}: {
  kind: AsyncStateKind
  title?: string
  description?: string
  requestId?: string
  traceId?: string
  issues?: ReadonlyArray<GraphQLIssue>
  onRetry?: () => void
  action?: ReactNode
  compact?: boolean
}) {
  const t = useTranslator()
  const resolvedTitle = title ?? t(defaultTitles[kind] ?? 'errorTitle')
  const resolvedDescription =
    description ??
    (defaultDescriptions[kind]
      ? t(defaultDescriptions[kind] as MessageKey)
      : undefined)

  if (kind === 'loading') {
    return (
      <div
        className={`flex flex-col items-center justify-center gap-3 rounded-field border border-border bg-surface text-center ${compact ? 'p-6' : 'p-10'}`}
        role="status"
        aria-live="polite"
        aria-label={resolvedTitle}
      >
        <Spinner aria-label={t('loading')} />
        <p className="text-sm font-medium">{resolvedTitle}</p>
        {resolvedDescription ? (
          <p className="max-w-md text-sm text-muted">{resolvedDescription}</p>
        ) : null}
      </div>
    )
  }

  if (kind === 'empty') {
    return (
      <EmptyState
        className={
          compact
            ? 'py-6 text-center'
            : 'rounded-field border border-border bg-surface p-8 text-center'
        }
      >
        <div className="mx-auto max-w-md">
          <p className="text-sm font-semibold">{resolvedTitle}</p>
          {resolvedDescription ? (
            <p className="mt-1.5 text-sm text-muted">{resolvedDescription}</p>
          ) : null}
          {action ? (
            <div className="mt-4 flex justify-center">{action}</div>
          ) : null}
        </div>
      </EmptyState>
    )
  }

  const status =
    kind === 'forbidden' || kind === 'notFound' || kind === 'unauthorized'
      ? 'danger'
      : kind === 'partial'
        ? 'warning'
        : 'danger'

  return (
    <Alert status={status}>
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{resolvedTitle}</Alert.Title>
        {resolvedDescription ? (
          <Alert.Description>{resolvedDescription}</Alert.Description>
        ) : null}
        <RequestCorrelation requestId={requestId} traceId={traceId} />
        <ErrorDetails issues={issues} />
        {onRetry || action ? (
          <div className="mt-3 flex flex-wrap gap-2">
            {onRetry ? (
              <Button size="sm" variant="secondary" onPress={onRetry}>
                {t('retry')}
              </Button>
            ) : null}
            {action}
          </div>
        ) : null}
      </Alert.Content>
    </Alert>
  )
}

export function LoadingBlock({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3" role="status" aria-live="polite">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-16 w-full rounded-field" />
      ))}
    </div>
  )
}
