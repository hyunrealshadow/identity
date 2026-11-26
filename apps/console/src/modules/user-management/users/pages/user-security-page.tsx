import { Alert, AlertDescription } from '@identity/ui/components/alert'
import { Badge } from '@identity/ui/components/badge'
import { Button, buttonVariants } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { Skeleton } from '@identity/ui/components/skeleton'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { DataTable, type DataTableColumn } from '@identity/ui/data-table'
import { ExternalLink, KeyRound, LogOut, Mail, ShieldOff, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { CopyableValue } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleUserSessionsDocument,
  type ConsoleUserSessionsQuery,
  type ConsoleUserSessionsQueryVariables,
} from '#/generated/graphql'
import type { EmailDeliveryFailure, UserRequiredAction } from '#/generated/graphql'
import { useAuth } from '#/lib/auth/context'
import { cursorPage } from '#/lib/cursor-page'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import type { GraphQLFailure, GraphQLIssue, GraphQLStepUp } from '#/lib/graphql/transport'
import { sameVariable, useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'
import { toast } from '#/lib/toast'
import {
  useCursorPagination,
  type PageCursor,
} from '#/lib/use-cursor-pagination'
import { useWorkspace } from '#/lib/workspace'
import { useUserDetailContext } from '../components/user-detail-context'
import { MutationFeedback } from '../components/user-feedback'
import { useUserMutations } from '../hooks/user-mutations'
import type { MutationFeedbackState } from '../lib/user-errors'
import { isCurrentUser, userManagementScope } from '../lib/user-scope'

const CHANGE_PASSWORD: UserRequiredAction = 'CHANGE_PASSWORD'

type Session = NonNullable<
  ConsoleUserSessionsQuery['user']
>['sessions']['edges'][number]['node']

const SESSION_PAGE_SIZE = 20

/** While an invitation email is queued, its status is read again this often, a few times. */
const QUEUED_REFRESH_MS = 3_000
const QUEUED_REFRESH_LIMIT = 10

const DELIVERY_FAILURE_KEYS: Record<EmailDeliveryFailure, MessageKey> = {
  EXPIRED: 'usersInvitationFailureExpired',
  NOT_CONFIGURED: 'usersInvitationFailureNotConfigured',
  INVALID_ADDRESS: 'usersInvitationFailureInvalidAddress',
  AUTHENTICATION_FAILED: 'usersInvitationFailureAuthentication',
  REJECTED: 'usersInvitationFailureRejected',
  TRANSPORT_FAILED: 'usersInvitationFailureTransport',
  SECRET_UNAVAILABLE: 'usersInvitationFailureSecret',
  MESSAGE_UNREADABLE: 'usersInvitationFailureUnreadable',
}

type Confirm = 'resetPassword' | 'resetMfa' | 'revokeAll' | { session: Session }

interface ResultShape {
  errors: ReadonlyArray<GraphQLIssue>
  failure?: GraphQLFailure
  stepUp?: GraphQLStepUp
  requestId?: string
  traceId?: string
  forbidden: boolean
}

function feedbackFrom(result: ResultShape, code: string): MutationFeedbackState {
  return {
    errors: result.errors,
    failure: result.failure ?? {
      kind: 'invalid_response',
      code,
      requestId: result.requestId,
      traceId: result.traceId,
    },
    stepUp: result.stepUp,
    requestId: result.requestId,
    traceId: result.traceId,
    forbidden: result.forbidden,
  }
}

/** User-agent parts the parser could not tell are reported as `UNKNOWN`. */
function known(value: string | null | undefined): value is string {
  return Boolean(value) && value !== 'UNKNOWN'
}

function sessionDevice(session: Session): string {
  const browser = [session.browserName, session.browserVersion].filter(known).join(' ')
  const os = [session.osName, session.osVersion].filter(known).join(' ')
  return [browser, os].filter(Boolean).join(' / ') || session.deviceName || session.deviceType || ''
}

function UserSecuritySkeleton({ label }: { label: string }) {
  return (
    <div
      role="status"
      aria-label={label}
      aria-busy="true"
      className="space-y-8"
    >
      <section className="space-y-3" aria-hidden="true">
        <div className="flex flex-col gap-3 px-1 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-2">
            <Skeleton className="h-5 w-28 rounded-lg" />
            <Skeleton className="h-4 w-72 max-w-full rounded-lg" />
          </div>
          <div className="flex flex-wrap gap-2">
            <Skeleton className="h-9 w-28 rounded-lg" />
            <Skeleton className="h-9 w-32 rounded-lg" />
          </div>
        </div>
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2">
          {Array.from({ length: 4 }, (_, index) => (
            <div
              key={index}
              className="flex items-center justify-between gap-3 bg-background px-4 py-3"
            >
              <Skeleton className="h-4 w-28 rounded-lg" />
              <Skeleton className="h-5 w-16 rounded-full" />
            </div>
          ))}
        </div>
      </section>
      <section className="space-y-3" aria-hidden="true">
        <div className="space-y-2 px-1">
          <Skeleton className="h-5 w-20 rounded-lg" />
          <Skeleton className="h-4 w-56 max-w-full rounded-lg" />
        </div>
        <div className="space-y-3 rounded-lg border border-border p-4">
          <Skeleton className="h-9 w-full rounded-lg" />
          <Skeleton className="h-10 w-full rounded-lg" />
          <Skeleton className="h-10 w-full rounded-lg" />
        </div>
      </section>
    </div>
  )
}

export function UserSecurityPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const { claims } = useAuth()
  const { accountUrl } = useRuntimeConfig()
  const detail = useUserDetailContext()
  const user = detail.user
  const workspace = useWorkspace()
  const scope = useMemo(
    () => userManagementScope(workspace.data?.effectivePermissions ?? null),
    [workspace.data?.effectivePermissions],
  )
  const mutations = useUserMutations()
  const [sessionCursor, setSessionCursor] = useState<PageCursor>({})
  const variables = useMemo<ConsoleUserSessionsQueryVariables | null>(
    () =>
      user
        ? {
            userId: user.id,
            ...cursorPage(SESSION_PAGE_SIZE, sessionCursor.after, sessionCursor.before),
          }
        : null,
    [user?.id, sessionCursor.after, sessionCursor.before],
  )
  const sessionsQuery = useConsoleQuery<
    ConsoleUserSessionsQuery,
    ConsoleUserSessionsQueryVariables
  >(
    ConsoleUserSessionsDocument,
    variables,
    Boolean(variables),
    'missing_user_sessions',
    { keepPreviousData: sameVariable('userId') },
  )
  const sessionPagination = useCursorPagination({
    search: sessionCursor,
    variables: variables ?? { userId: '', first: SESSION_PAGE_SIZE },
    onNavigate: setSessionCursor,
  })
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<MutationFeedbackState | null>(null)
  const [temporaryPassword, setTemporaryPassword] = useState<string | null>(null)
  const confirmDialog = useOverlayState()
  const revealDialog = useOverlayState()

  // A queued invitation email is usually delivered within seconds; follow it
  // for a short while so the panel shows the outcome.
  const invitation = user?.invitation ?? null
  const invitationStatus = invitation?.delivery.status ?? null
  const invitationSentAt = invitation?.sentAt ?? null
  const userId = user?.id ?? null
  const queuedRefreshes = useRef(0)
  const refreshDetailRef = useRef(detail.refresh)
  refreshDetailRef.current = detail.refresh
  const isRefreshing = detail.refreshing
  useEffect(() => {
    queuedRefreshes.current = 0
    setSessionCursor({})
  }, [userId, invitationSentAt])
  useEffect(() => {
    if (invitationStatus !== 'QUEUED') {
      queuedRefreshes.current = 0
      return
    }
    if (isRefreshing || queuedRefreshes.current >= QUEUED_REFRESH_LIMIT) return
    const timer = window.setTimeout(() => {
      queuedRefreshes.current += 1
      void refreshDetailRef.current()
    }, QUEUED_REFRESH_MS)
    return () => window.clearTimeout(timer)
  }, [invitationStatus, invitationSentAt, userId, isRefreshing])

  if (!user) {
    if (detail.status === 'idle' || detail.status === 'loading') {
      return <UserSecuritySkeleton label={t('usersDetailLoading')} />
    }
    return null
  }
  const selfTarget = isCurrentUser(user.id, claims?.sub)
  const methods = user.authenticationMethods
  const changeRequired = (user.requiredActions ?? []).includes(CHANGE_PASSWORD)
  const otherRequiredActions = (user.requiredActions ?? []).filter(
    (action) => action !== CHANGE_PASSWORD,
  )
  const hasSecondFactor = Boolean(
    methods && (methods.authenticatorApp || methods.recoveryCodes || methods.passkey),
  )
  const sessionsConnection = sessionsQuery.data?.user?.sessions ?? null
  const sessions = sessionsConnection?.edges.map((edge) => edge.node) ?? []

  function ask(next: Confirm) {
    setFeedback(null)
    setConfirm(next)
    confirmDialog.open()
  }

  async function run() {
    if (!user || !confirm) return
    setPending(true)
    setFeedback(null)
    const state = { id: user.id, expectedVersion: user.version }
    try {
      if (confirm === 'resetPassword') {
        const result = await mutations.resetPassword(state)
        confirmDialog.close()
        const payload = result.data?.resetUserPassword
        if (!payload) return setFeedback(feedbackFrom(result, 'missing_reset_password_payload'))
        setTemporaryPassword(payload.temporaryPassword)
        revealDialog.open()
        void detail.reload()
        void sessionsQuery.refresh()
        return
      }
      if (confirm === 'resetMfa') {
        const result = await mutations.resetMfa(state)
        confirmDialog.close()
        if (!result.data?.resetUserMfa) {
          return setFeedback(feedbackFrom(result, 'missing_reset_mfa_payload'))
        }
        toast.success(t('usersSecurityMfaResetToast'))
        void detail.reload()
        void sessionsQuery.refresh()
        return
      }
      const result = await mutations.revokeSessions({
        id: user.id,
        sessionIds: confirm === 'revokeAll' ? null : [confirm.session.id],
      })
      confirmDialog.close()
      if (!result.data?.revokeUserSessions) {
        return setFeedback(feedbackFrom(result, 'missing_revoke_sessions_payload'))
      }
      toast.success(
        t(confirm === 'revokeAll' ? 'usersSessionsRevokedAllToast' : 'usersSessionRevokedToast'),
      )
      void sessionsQuery.refresh()
    } catch {
      confirmDialog.close()
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_security_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  async function sendInvitation() {
    if (!user) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.sendInvitation({ id: user.id })
      if (!result.data?.sendUserInvitation) {
        return setFeedback(feedbackFrom(result, 'missing_send_invitation_payload'))
      }
      toast.success(t('usersInvitationSentToast'))
      queuedRefreshes.current = 0
      void detail.reload()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_security_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  async function setChangeRequired(required: boolean) {
    if (!user) return
    setPending(true)
    setFeedback(null)
    // Replace only this action; any other required action stays as it is.
    const others = (user.requiredActions ?? []).filter(
      (action) => action !== CHANGE_PASSWORD,
    )
    try {
      const result = await mutations.update({
        id: user.id,
        expectedVersion: user.version,
        requiredActions: required ? [...others, CHANGE_PASSWORD] : others,
      })
      if (!result.data?.updateUser) {
        return setFeedback(feedbackFrom(result, 'missing_update_user_payload'))
      }
      toast.success(
        t(required ? 'usersSecurityChangeRequiredToast' : 'usersSecurityChangeNotRequiredToast'),
      )
      void detail.reload()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_security_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  const confirmText: Record<'resetPassword' | 'resetMfa' | 'revokeAll' | 'session', {
    title: MessageKey
    description: MessageKey
    action: MessageKey
  }> = {
    resetPassword: {
      title: 'usersSecurityResetPasswordTitle',
      description: 'usersSecurityResetPasswordDescription',
      action: 'usersSecurityResetPassword',
    },
    resetMfa: {
      title: 'usersSecurityResetMfaTitle',
      description: 'usersSecurityResetMfaDescription',
      action: 'usersSecurityResetMfa',
    },
    revokeAll: {
      title: 'usersSessionsRevokeAllTitle',
      description: 'usersSessionsRevokeAllDescription',
      action: 'usersSessionsRevokeAll',
    },
    session: {
      title: 'usersSessionRevokeTitle',
      description: 'usersSessionRevokeDescription',
      action: 'tableActionRevoke',
    },
  }
  const confirmKey = confirm === null ? 'session' : typeof confirm === 'string' ? confirm : 'session'
  const text = confirmText[confirmKey]

  const methodRows: ReadonlyArray<{ label: MessageKey; on: boolean | undefined }> = [
    { label: 'usersSecurityMethodPassword', on: methods?.password },
    { label: 'usersSecurityMethodAuthenticator', on: methods?.authenticatorApp },
    { label: 'usersSecurityMethodRecoveryCodes', on: methods?.recoveryCodes },
    { label: 'usersSecurityMethodPasskey', on: methods?.passkey },
  ]

  const columns: DataTableColumn[] = [
    { id: 'device', label: t('usersSessionsColumnDevice'), primary: true },
    { id: 'ip', label: t('usersSessionsColumnIp'), primary: false },
    { id: 'active', label: t('usersSessionsColumnLastActive'), primary: false },
    { id: 'created', label: t('usersSessionsColumnSignedIn'), primary: false },
    { id: 'actions', label: t('clientsColumnActions'), primary: false },
  ]

  return (
    <div className="space-y-8">
      {feedback ? (
        <MutationFeedback
          feedback={feedback}
          onReload={() => void detail.reload()}
          reloadPending={detail.refreshing}
        />
      ) : null}

      <section className="space-y-3" aria-labelledby="user-security-methods">
        <header className="flex flex-col gap-3 px-1 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <h2 id="user-security-methods" className="text-sm font-semibold">
              {t('usersSecurityMethodsTitle')}
            </h2>
            <p className="mt-0.5 max-w-2xl text-xs leading-5 text-muted-foreground">
              {t(selfTarget ? 'usersSecuritySelfMethodsDescription' : 'usersSecurityMethodsDescription')}
            </p>
          </div>
          {selfTarget ? (
            <a href={accountUrl} className={buttonVariants({ variant: 'outline' })}>
              <ExternalLink className="size-4" aria-hidden="true" />
              {t('usersSecuritySelfAccountCenter')}
            </a>
          ) : scope.credentials ? (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" disabled={pending} onClick={() => ask('resetPassword')}>
                <KeyRound className="size-4" aria-hidden="true" />
                {t('usersSecurityResetPassword')}
              </Button>
              <Button
                variant="outline"
                disabled={pending || !hasSecondFactor || !methods?.password}
                onClick={() => ask('resetMfa')}
              >
                <ShieldOff className="size-4" aria-hidden="true" />
                {t('usersSecurityResetMfa')}
              </Button>
            </div>
          ) : null}
        </header>
        <dl className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2">
          {methodRows.map((row) => (
            <div key={row.label} className="flex items-center justify-between gap-3 bg-background px-4 py-3">
              <dt className="text-sm">{t(row.label)}</dt>
              <dd>
                <Badge variant="secondary" className={row.on ? 'text-success' : 'text-muted-foreground'}>
                  {t(row.on ? 'usersSecurityMethodSet' : 'usersSecurityMethodNotSet')}
                </Badge>
              </dd>
            </div>
          ))}
        </dl>
        {methods && !methods.password ? (
          <div className="flex flex-col gap-3 rounded-lg border border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium">{t('usersInvitationTitle')}</p>
              <p className="text-xs leading-5 text-muted-foreground">
                {user.invitation
                  ? new Date(user.invitation.expiresAt).getTime() <= Date.now()
                    ? t('usersInvitationExpired', {
                        expiresAt: formatDateTime(user.invitation.expiresAt, locale, timeZone),
                      })
                    : t('usersInvitationPending', {
                        sentAt: formatDateTime(user.invitation.sentAt, locale, timeZone),
                        expiresAt: formatDateTime(user.invitation.expiresAt, locale, timeZone),
                      })
                  : t('usersInvitationNone')}
              </p>
              {user.invitation ? (
                <InvitationDeliveryLine
                  delivery={user.invitation.delivery}
                  locale={locale}
                  timeZone={timeZone}
                />
              ) : null}
            </div>
            {scope.credentials && !selfTarget ? (
              <Button
                variant="outline"
                size="sm"
                disabled={pending}
                onClick={() => void sendInvitation()}
              >
                <Mail className="size-4" aria-hidden="true" />
                {t(user.invitation ? 'usersInvitationResend' : 'usersInvitationSend')}
              </Button>
            ) : null}
          </div>
        ) : null}
        {methods?.password ? (
          <div className="flex flex-col gap-3 rounded-lg border border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium">{t('usersSecurityChangeRequired')}</p>
              <p className="text-xs leading-5 text-muted-foreground">
                {t(
                  changeRequired
                    ? 'usersSecurityChangeRequiredOn'
                    : 'usersSecurityChangeRequiredOff',
                )}
              </p>
            </div>
            {scope.update && (!selfTarget || (changeRequired && otherRequiredActions.length === 0)) ? (
              <Button
                variant="outline"
                size="sm"
                disabled={pending}
                onClick={() => void setChangeRequired(!changeRequired)}
              >
                {t(
                  changeRequired
                    ? 'usersSecurityChangeRequiredClear'
                    : 'usersSecurityChangeRequiredSet',
                )}
              </Button>
            ) : null}
          </div>
        ) : null}
      </section>

      <section className="space-y-3" aria-labelledby="user-security-sessions">
        <header className="flex flex-col gap-3 px-1 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <h2 id="user-security-sessions" className="text-sm font-semibold">
              {t('usersSessionsTitle')}
            </h2>
            <p className="mt-0.5 max-w-2xl text-xs leading-5 text-muted-foreground">
              {t('usersSessionsDescription')}
            </p>
          </div>
          {scope.sessions && sessions.length ? (
            <Button variant="outline" disabled={pending} onClick={() => ask('revokeAll')}>
              <LogOut className="size-4" aria-hidden="true" />
              {t('usersSessionsRevokeAll')}
            </Button>
          ) : null}
        </header>
        {sessionsQuery.status === 'error' ? (
          <AsyncState
            kind={sessionsQuery.forbidden ? 'forbidden' : 'error'}
            compact
            title={t(failureTitleKey(sessionsQuery.failure, sessionsQuery.forbidden))}
            description={t(failureDescriptionKey(sessionsQuery.failure, sessionsQuery.forbidden))}
            requestId={sessionsQuery.requestId}
            traceId={sessionsQuery.traceId}
            onRetry={() => void sessionsQuery.refresh()}
          />
        ) : (
          <DataTable
            label={t('usersSessionsTitle')}
            loading={sessionsQuery.status === 'idle' || sessionsQuery.status === 'loading' || sessionsQuery.refreshing}
            loadingLabel={t('tableLoading')}
            loadingRows={2}
            minWidth={720}
            density="compact"
            columns={columns}
          >
            <DataTable.Body
              renderEmptyState={() => (
                <AsyncState kind="empty" compact title={t('usersSessionsEmpty')} />
              )}
            >
              {sessions.map((session) => {
                const device = sessionDevice(session)
                return (
                  <DataTable.Row key={session.id} id={session.id}>
                    <DataTable.Cell>
                      <span className="text-sm">{device || t('usersSessionsUnknownDevice')}</span>
                    </DataTable.Cell>
                    <DataTable.Cell>
                      <span className="font-mono text-xs">{session.ipAddress ?? ''}</span>
                    </DataTable.Cell>
                    <DataTable.Cell>
                      <span className="whitespace-nowrap text-sm">
                        {formatDateTime(session.lastActiveAt, locale, timeZone)}
                      </span>
                    </DataTable.Cell>
                    <DataTable.Cell>
                      <span className="whitespace-nowrap text-sm">
                        {formatDateTime(session.createdAt, locale, timeZone)}
                      </span>
                    </DataTable.Cell>
                    <DataTable.Cell>
                      {scope.sessions ? (
                        <TableRowActions
                          subject={device || session.id}
                          actions={[
                            {
                              id: 'revoke',
                              label: t('tableActionRevoke'),
                              section: 'danger',
                              onAction: () => ask({ session }),
                            },
                          ]}
                        />
                      ) : null}
                    </DataTable.Cell>
                  </DataTable.Row>
                )
              })}
            </DataTable.Body>
          </DataTable>
        )}
        {sessionsConnection ? (
          <CursorPagination
            label={t('usersSessionsTitle')}
            pageCount={sessions.length}
            controller={sessionPagination}
            pageInfo={sessionsConnection.pageInfo}
            isDisabled={sessionsQuery.refreshing || sessionsQuery.status !== 'ready'}
          />
        ) : null}
      </section>

      <ConfirmationDialog
        state={confirmDialog}
        title={t(text.title)}
        description={t(text.description, { username: user.username })}
        confirmLabel={t(text.action)}
        destructive
        pending={pending}
        onConfirm={() => void run()}
      />

      <Dialog
        open={revealDialog.isOpen}
        onOpenChange={(open) => {
          revealDialog.setOpen(open)
          if (!open) setTemporaryPassword(null)
        }}
        disablePointerDismissal
      >
        <DialogContent showCloseButton={false}>
          <DialogHeader>
            <DialogTitle>{t('usersSecurityTemporaryPasswordTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Alert className="text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertDescription>{t('usersSecurityTemporaryPasswordWarning')}</AlertDescription>
            </Alert>
            {temporaryPassword ? (
              <CopyableValue
                value={temporaryPassword}
                label={t('usersSecurityTemporaryPassword')}
                layout="block"
                size="sm"
              />
            ) : null}
          </div>
          <DialogFooter>
            <Button
              onClick={() => {
                setTemporaryPassword(null)
                revealDialog.close()
              }}
            >
              {t('usersSecurityTemporaryPasswordDone')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function InvitationDeliveryLine({
  delivery,
  locale,
  timeZone,
}: {
  delivery: { status: string; failure?: EmailDeliveryFailure | null; updatedAt: string }
  locale: Parameters<typeof formatDateTime>[1]
  timeZone: Parameters<typeof formatDateTime>[2]
}) {
  const t = useTranslator()
  const at = formatDateTime(delivery.updatedAt, locale, timeZone)
  if (delivery.status === 'DELIVERED') {
    return (
      <p className="text-xs leading-5 text-success">
        {t('usersInvitationDelivered', { at })}
      </p>
    )
  }
  if (delivery.status === 'FAILED') {
    return (
      <p className="flex items-start gap-1.5 text-xs leading-5 text-destructive" role="status">
        <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        {t('usersInvitationFailed', {
          at,
          reason: t(delivery.failure ? DELIVERY_FAILURE_KEYS[delivery.failure] : 'usersInvitationFailureTransport'),
        })}
      </p>
    )
  }
  return (
    <p className="text-xs leading-5 text-muted-foreground" role="status">
      {t('usersInvitationQueued')}
    </p>
  )
}
