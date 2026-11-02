import { Alert, Button, Skeleton } from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Check, Copy, Ellipsis, Pencil } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import { useAuth } from '#/lib/auth/context'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { UserDetailTabs } from '#/modules/user-management/components/detail-tabs'
import { useUserDetail } from '../hooks/use-user-detail'
import { isCurrentUser, userManagementScope } from '../lib/user-scope'
import { UserReadRestricted } from './user-access'
import { UserDetailContext } from './user-detail-context'
import { UserDetailActionSkeleton } from './user-detail-skeleton'
import { UserNoticeAlert, type UserNotice } from './user-feedback'
import { UserStateActions, type UserStateAction } from './user-state-actions'
import { UserStatusBadges } from './user-status'

export function UserDetailLayout({
  userId,
  current,
  children,
}: {
  userId: string
  current:
    | '/users/$userId'
    | '/users/$userId/groups'
    | '/users/$userId/roles'
    | '/users/$userId/permissions'
  children: ReactNode
}) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const { claims } = useAuth()
  const permissions = workspace.data?.effectivePermissions ?? null
  const scope = useMemo(() => userManagementScope(permissions), [permissions])
  const detail = useUserDetail(userId, scope.read)
  const [notice, setNotice] = useState<UserNotice | null>(null)
  const [accessEnded, setAccessEnded] = useState(false)
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)
  const workspaceLoading =
    (workspace.status === 'idle' || workspace.status === 'loading') &&
    !permissions
  const loading =
    workspaceLoading ||
    (scope.read &&
      !detail.user &&
      (detail.status === 'idle' || detail.status === 'loading'))
  const user = detail.user
  useBreadcrumbLabel(`/users/${userId}`, user?.username)

  useEffect(() => {
    if (!copied && !copyFailed) return
    const timeout = window.setTimeout(() => {
      setCopied(false)
      setCopyFailed(false)
    }, 2500)
    return () => window.clearTimeout(timeout)
  }, [copied, copyFailed])

  async function copyId() {
    if (!user) return
    try {
      await navigator.clipboard.writeText(user.id)
      setCopied(true)
      setCopyFailed(false)
    } catch {
      setCopyFailed(true)
    }
  }

  function reloadAfterWrite(): Promise<boolean> {
    return detail.reload().then((outcome) => {
      if (outcome.kind === 'ready') {
        setAccessEnded(false)
        return true
      }
      if (outcome.kind === 'forbidden' || outcome.kind === 'unauthorized')
        setAccessEnded(true)
      return false
    })
  }

  function handleStateCommitted(
    action: UserStateAction,
    payload: { userId: string; version: string },
    _partial: boolean,
    requestId?: string,
    traceId?: string,
  ) {
    if (action === 'disable' && isCurrentUser(payload.userId, claims?.sub)) {
      setAccessEnded(true)
      setNotice({
        kind: 'warning',
        title: t('usersSelfDisabledTitle'),
        description: t('usersSelfDisabledDescription'),
        requestId,
        traceId,
      })
      return
    }
    void detail.reload().then((outcome) => {
      const ready = outcome.kind === 'ready'
      const lost =
        outcome.kind === 'forbidden' || outcome.kind === 'unauthorized'
      setAccessEnded(lost)
      setNotice({
        kind: ready ? 'success' : 'warning',
        title: t(
          ready
            ? 'usersStateSavedTitle'
            : lost
              ? 'usersStateAccessLostTitle'
              : 'usersStateRefreshFailedTitle',
        ),
        description: t(
          ready
            ? 'usersStateCommitted'
            : lost
              ? 'usersStateAccessLostDescription'
              : 'usersStateRefreshFailedDescription',
        ),
        requestId,
        traceId,
      })
    })
  }

  let failure: ReactNode = null
  if (!workspaceLoading && !permissions) {
    failure = workspace.stepUp ? (
      <StepUpPanel
        stepUp={workspace.stepUp}
        hideDetails
        description={t('usersStepUpDescription')}
        note={t('usersStepUpNote')}
      />
    ) : (
      <AsyncState
        kind={
          workspace.forbidden
            ? 'forbidden'
            : workspace.status === 'error'
              ? 'error'
              : 'partial'
        }
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
  } else if (!workspaceLoading && !scope.read) {
    failure = (
      <UserReadRestricted
        scope={scope}
        onCreate={() => void navigate({ to: '/users/new' })}
        onGoHome={() => void navigate({ to: '/' })}
      />
    )
  } else if (detail.notFound) {
    failure = (
      <AsyncState
        kind="notFound"
        title={t('notFoundTitle')}
        description={t('notFoundDescription')}
      />
    )
  } else if (detail.status === 'error') {
    failure = detail.stepUp ? (
      <StepUpPanel
        stepUp={detail.stepUp}
        hideDetails
        description={t('usersStepUpDescription')}
        note={t('usersStepUpNote')}
      />
    ) : (
      <AsyncState
        kind={detail.forbidden ? 'forbidden' : 'error'}
        title={t(failureTitleKey(detail.failure, detail.forbidden))}
        description={t(failureDescriptionKey(detail.failure, detail.forbidden))}
        requestId={detail.requestId}
        traceId={detail.traceId}
        issues={detail.errors}
        onRetry={() => void detail.refresh()}
      />
    )
  }

  const name = user
    ? [user.givenName, user.familyName].filter(Boolean).join(' ') ||
      user.nickname ||
      user.username
    : ''
  const stateMenuUser =
    user && (typeof user.enabled === 'boolean' || user.locked === true)
      ? user
      : null

  return (
    <UserDetailContext value={detail}>
      <div className="mb-6">
        <Button
          variant="ghost"
          className="mb-5 -ml-3"
          onPress={() => void navigate({ to: '/users' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToUsers')}
        </Button>
        <header
          className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between"
          aria-label={t('usersDetailTitle')}
        >
          <div className="flex min-w-0 items-center gap-4">
            {user ? (
              <AccountAvatar
                name={name}
                label={t('usersDetailAvatarLabel', { username: user.username })}
                size="lg"
                className="size-16 shrink-0 text-lg"
              />
            ) : (
              <Skeleton className="size-16 shrink-0 rounded-field" />
            )}
            <div className="min-w-0 space-y-1.5">
              <div className="flex flex-wrap items-center gap-3">
                {user ? (
                  <>
                    <h1 className="break-all text-2xl font-semibold tracking-tight">
                      {user.username}
                    </h1>
                    <UserStatusBadges user={user} />
                  </>
                ) : (
                  <Skeleton className="h-8 w-44 max-w-full rounded-field" />
                )}
              </div>
              {user ? (
                <p className="break-all text-sm text-muted">{user.email}</p>
              ) : (
                <Skeleton className="h-5 w-52 max-w-full rounded-field" />
              )}
              {user ? (
                <div className="flex min-w-0 items-center gap-2 text-xs text-muted">
                  <span className="shrink-0">{t('usersUserIdLabel')}</span>
                  <code
                    className="min-w-0 truncate rounded-field bg-default px-2 py-1"
                    title={user.id}
                  >
                    {user.id}
                  </code>
                  <Button
                    isIconOnly
                    size="sm"
                    variant="ghost"
                    aria-label={t(copied ? 'usersIdCopied' : 'usersCopyId')}
                    onPress={() => void copyId()}
                  >
                    {copied ? (
                      <Check className="size-3.5" />
                    ) : (
                      <Copy className="size-3.5" />
                    )}
                  </Button>
                  <span className="sr-only" role="status">
                    {copied
                      ? t('usersIdCopied')
                      : copyFailed
                        ? t('usersIdCopyFailed')
                        : ''}
                  </span>
                </div>
              ) : (
                <Skeleton className="h-9 w-64 max-w-full rounded-field md:h-8" />
              )}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {scope.update && user && !accessEnded ? (
              <Button
                onPress={() =>
                  void navigate({
                    to: '/users/$userId/edit',
                    params: { userId },
                  })
                }
              >
                <Pencil className="size-4" aria-hidden="true" />
                {t('usersEditAction')}
              </Button>
            ) : loading && (workspaceLoading || scope.update) ? (
              <UserDetailActionSkeleton
                label={t('usersEditAction')}
                icon={<Pencil className="size-4" />}
              />
            ) : null}
            {!accessEnded && scope.state && !false && stateMenuUser ? (
              <UserStateActions
                user={stateMenuUser}
                presentation="menu"
                onCommitted={handleStateCommitted}
                onReload={reloadAfterWrite}
              />
            ) : loading && (workspaceLoading || (scope.state && !false)) ? (
              <UserDetailActionSkeleton
                label={t('usersMoreActions')}
                icon={<Ellipsis className="size-4" />}
              />
            ) : null}
          </div>
        </header>
      </div>
      <UserDetailTabs userId={userId} current={current} />
      <div className="space-y-5">
        {notice ? (
          <UserNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}
        {detail.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('usersPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('usersPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={detail.requestId}
                traceId={detail.traceId}
              />
              <ErrorDetails issues={detail.errors} />
            </Alert.Content>
          </Alert>
        ) : null}
        {failure || children}
      </div>
    </UserDetailContext>
  )
}
