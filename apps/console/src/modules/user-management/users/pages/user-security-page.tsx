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
import { ExternalLink, KeyRound, LogOut, ShieldOff, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { CopyableValue } from '#/components/copy-button'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleUserSessionsDocument,
  type ConsoleUserSessionsQuery,
  type ConsoleUserSessionsQueryVariables,
} from '#/generated/graphql'
import { useAuth } from '#/lib/auth/context'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import type { GraphQLFailure, GraphQLIssue, GraphQLStepUp } from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'
import { toast } from '#/lib/toast'
import { useWorkspace } from '#/lib/workspace'
import { useUserDetailContext } from '../components/user-detail-context'
import { MutationFeedback } from '../components/user-feedback'
import { useUserMutations } from '../hooks/user-mutations'
import type { MutationFeedbackState } from '../lib/user-errors'
import { isCurrentUser, userManagementScope } from '../lib/user-scope'

type Session = NonNullable<
  ConsoleUserSessionsQuery['user']
>['sessions']['edges'][number]['node']

/** At most this many sessions are listed; revoking all covers the rest. */
const SESSION_PAGE_SIZE = 50

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
  const variables = useMemo(
    () => (user ? { userId: user.id, first: SESSION_PAGE_SIZE } : null),
    [user?.id],
  )
  const sessionsQuery = useConsoleQuery<
    ConsoleUserSessionsQuery,
    ConsoleUserSessionsQueryVariables
  >(ConsoleUserSessionsDocument, variables, Boolean(variables), 'missing_user_sessions')
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<MutationFeedbackState | null>(null)
  const [temporaryPassword, setTemporaryPassword] = useState<string | null>(null)
  const confirmDialog = useOverlayState()
  const revealDialog = useOverlayState()

  if (!user) {
    if (detail.status === 'idle' || detail.status === 'loading') {
      return <UserSecuritySkeleton label={t('usersDetailLoading')} />
    }
    return null
  }
  const selfTarget = isCurrentUser(user.id, claims?.sub)
  const methods = user.authenticationMethods
  const hasSecondFactor = Boolean(
    methods && (methods.authenticatorApp || methods.recoveryCodes || methods.passkey),
  )
  const sessions = sessionsQuery.data?.user?.sessions.edges.map((edge) => edge.node) ?? []
  const moreSessions = sessionsQuery.data?.user?.sessions.pageInfo.hasNextPage ?? false

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

  async function setChangeRequired(required: boolean) {
    if (!user) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.update({
        id: user.id,
        expectedVersion: user.version,
        passwordChangeRequired: required,
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
        {methods?.password ? (
          <div className="flex flex-col gap-3 rounded-lg border border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium">{t('usersSecurityChangeRequired')}</p>
              <p className="text-xs leading-5 text-muted-foreground">
                {t(
                  user.passwordChangeRequired
                    ? 'usersSecurityChangeRequiredOn'
                    : 'usersSecurityChangeRequiredOff',
                )}
              </p>
            </div>
            {scope.update && !selfTarget ? (
              <Button
                variant="outline"
                size="sm"
                disabled={pending}
                onClick={() => void setChangeRequired(!user.passwordChangeRequired)}
              >
                {t(
                  user.passwordChangeRequired
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
              {t(moreSessions ? 'usersSessionsDescriptionMore' : 'usersSessionsDescription', {
                count: SESSION_PAGE_SIZE,
              })}
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
