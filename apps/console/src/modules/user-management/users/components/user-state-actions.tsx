import { Alert, AlertDescription } from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { Spinner } from '@identity/ui/components/spinner'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { Ellipsis, LockOpen, Power, PowerOff, TriangleAlert } from 'lucide-react'
import { useRef, useState } from 'react'

import { toast } from '#/lib/toast'
import { MutationFeedback } from '#/modules/user-management/users/components/user-feedback'
import type { ProjectedUser } from '#/modules/user-management/users/lib/user-form'
import type {
  MutationFeedbackState,
} from '#/modules/user-management/users/lib/user-errors'
import { useUserMutations } from '#/modules/user-management/users/hooks/user-mutations'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useTranslator, type MessageKey } from '#/lib/i18n'

export type UserStateAction = 'enable' | 'disable' | 'unlock'

type OverlayState = ReturnType<typeof useOverlayState>

interface ActionMeta {
  title: MessageKey
  description: MessageKey
  confirm: MessageKey
  toast: MessageKey
}

const ACTION_META: Record<UserStateAction, ActionMeta> = {
  enable: {
    title: 'usersEnableTitle',
    description: 'usersEnableDescription',
    confirm: 'usersStateConfirmEnable',
    toast: 'usersStateEnabledToast',
  },
  disable: {
    title: 'usersDisableTitle',
    description: 'usersDisableDescription',
    confirm: 'usersStateConfirmDisable',
    toast: 'usersStateDisabledToast',
  },
  unlock: {
    title: 'usersUnlockTitle',
    description: 'usersUnlockDescription',
    confirm: 'usersStateConfirmUnlock',
    toast: 'usersStateUnlockedToast',
  },
}

interface StateResultShape {
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  stepUp?: GraphQLStepUp
  requestId?: string
  traceId?: string
  partial: boolean
  forbidden: boolean
}

export function UserStateActions({
  user,
  onCommitted,
  onReload,
  presentation = 'buttons',
}: {
  user: ProjectedUser
  onCommitted: (
    action: UserStateAction,
    payload: { userId: string; version: string },
    partial: boolean,
    requestId?: string,
    traceId?: string,
  ) => void
  onReload: () => Promise<boolean>
  presentation?: 'buttons' | 'menu'
}) {
  const t = useTranslator()
  const enableState = useOverlayState()
  const disableState = useOverlayState()
  const unlockState = useOverlayState()
  const versionReady = Boolean(user.version)
  const showEnable = user.enabled === false
  const showDisable = user.enabled === true
  const showUnlock = user.locked === true
  const hasAction = showEnable || showDisable || showUnlock

  const dialogs = (
    <>
      <UserStateDialog
        key={`enable:${user.id}`}
        state={enableState}
        action="enable"
        user={user}
        onCommitted={onCommitted}
        onReload={onReload}
      />
      <UserStateDialog
        key={`disable:${user.id}`}
        state={disableState}
        action="disable"
        user={user}
        onCommitted={onCommitted}
        onReload={onReload}
      />
      <UserStateDialog
        key={`unlock:${user.id}`}
        state={unlockState}
        action="unlock"
        user={user}
        onCommitted={onCommitted}
        onReload={onReload}
      />
    </>
  )

  if (presentation === 'menu') {
    return (
      <>
        {hasAction ? (
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button
                  variant="secondary"
                  aria-label={t('usersMoreActions')}
                />
              }
            >
              <Ellipsis className="size-4" aria-hidden="true" />
              {t('usersMoreActions')}
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="min-w-48"
              aria-label={t('usersMoreActions')}
            >
              {showEnable ? (
                <DropdownMenuItem
                  disabled={!versionReady}
                  onClick={enableState.open}
                >
                  <Power
                    className="size-4 text-muted-foreground"
                    aria-hidden="true"
                  />
                  {t('usersEnableAction')}
                </DropdownMenuItem>
              ) : null}
              {showDisable ? (
                <DropdownMenuItem
                  variant="destructive"
                  disabled={!versionReady}
                  onClick={disableState.open}
                >
                  <PowerOff className="size-4" aria-hidden="true" />
                  {t('usersDisableAction')}
                </DropdownMenuItem>
              ) : null}
              {showUnlock ? (
                <DropdownMenuItem
                  disabled={!versionReady}
                  onClick={unlockState.open}
                >
                  <LockOpen
                    className="size-4 text-muted-foreground"
                    aria-hidden="true"
                  />
                  {t('usersUnlockAction')}
                </DropdownMenuItem>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
        {dialogs}
      </>
    )
  }

  return (
    <div>
      {!versionReady ? (
        <p className="mb-3 text-xs leading-5 text-destructive">
          {t('usersStateVersionUnavailable')}
        </p>
      ) : null}
      {hasAction ? (
        <div className="flex flex-wrap gap-2">
          {showEnable ? (
            <Button
              variant="secondary"
              disabled={!versionReady}
              onClick={enableState.open}
            >
              <Power className="size-4" aria-hidden="true" />
              {t('usersEnableAction')}
            </Button>
          ) : null}
          {showDisable ? (
            <Button
              variant="destructive"
              disabled={!versionReady}
              onClick={disableState.open}
            >
              <PowerOff className="size-4" aria-hidden="true" />
              {t('usersDisableAction')}
            </Button>
          ) : null}
          {showUnlock ? (
            <Button
              variant="secondary"
              disabled={!versionReady}
              onClick={unlockState.open}
            >
              <LockOpen className="size-4" aria-hidden="true" />
              {t('usersUnlockAction')}
            </Button>
          ) : null}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">{t('usersStateNoAction')}</p>
      )}

      {dialogs}
    </div>
  )
}

function UserStateDialog({
  state,
  action,
  user,
  onCommitted,
  onReload,
}: {
  state: OverlayState
  action: UserStateAction
  user: ProjectedUser
  onCommitted: (
    action: UserStateAction,
    payload: { userId: string; version: string },
    partial: boolean,
    requestId?: string,
    traceId?: string,
  ) => void
  onReload: () => Promise<boolean>
}) {
  const t = useTranslator()
  const mutations = useUserMutations()
  const meta = ACTION_META[action]
  const submitting = useRef(false)
  const [feedback, setFeedback] = useState<MutationFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const [reloading, setReloading] = useState(false)

  function finish(
    payload: { userId: string; version: string } | null,
    result: StateResultShape,
  ) {
    if (!payload) {
      setFeedback({
        errors: result.errors,
        failure:
          result.failure ??
          {
            kind: 'invalid_response',
            code: 'missing_user_state_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
        stepUp: result.stepUp,
        requestId: result.requestId,
        traceId: result.traceId,
        forbidden: result.forbidden,
      })
      return
    }

    state.close()
    toast.success(t(meta.toast), {
      description: t('usersStateCommitted'),
    })
    if (result.partial) {
      toast.warning(t('usersPartialMutationNote'))
    }
    onCommitted(
      action,
      payload,
      result.partial,
      result.requestId,
      result.traceId,
    )
  }

  async function submit() {
    if (submitting.current) return
    const expectedVersion = user.version
    if (!expectedVersion) return

    submitting.current = true
    setPending(true)
    setFeedback(null)

    const input = {
      id: user.id,
      expectedVersion,
    }

    try {
      if (action === 'enable') {
        const result = await mutations.enable(input)
        finish(result.data?.enableUser ?? null, result)
        return
      }
      if (action === 'disable') {
        const result = await mutations.disable(input)
        finish(result.data?.disableUser ?? null, result)
        return
      }
      const result = await mutations.unlock(input)
      finish(result.data?.unlockUser ?? null, result)
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_state_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  async function reloadConflict() {
    setReloading(true)
    try {
      const ready = await onReload()
      if (ready) {
        setFeedback(null)
      }
    } finally {
      setReloading(false)
    }
  }

  const versionAvailable = Boolean(user.version)
  const busy = pending || reloading

  return (
    <Dialog
      open={state.isOpen}
      onOpenChange={(open) => {
        if (!open && busy) return
        state.setOpen(open)
      }}
    >
      <DialogContent showCloseButton={!busy} closeLabel={t('close')}>
        <DialogHeader>
          <DialogTitle>{t(meta.title)}</DialogTitle>
        </DialogHeader>
        <div>
          <p className="text-sm leading-6 text-muted-foreground">
            {t(meta.description)}
          </p>

          {!versionAvailable ? (
            <Alert variant="default" className="mt-3 text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertDescription>
                {t('usersStateVersionUnavailable')}
              </AlertDescription>
            </Alert>
          ) : null}

          <dl className="mt-4 grid gap-3 rounded-lg border border-border p-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium text-muted-foreground">
                {t('usersStateTarget')}
              </dt>
              <dd className="mt-0.5 break-words">{user.username}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-muted-foreground">
                {t('usersUserIdLabel')}
              </dt>
              <dd className="mt-0.5 break-all font-mono text-xs">{user.id}</dd>
            </div>
          </dl>

          {feedback ? (
            <div className="mt-4">
              <MutationFeedback
                feedback={feedback}
                onReload={() => void reloadConflict()}
                reloadPending={reloading}
              />
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="secondary"
            disabled={busy}
            onClick={() => state.close()}
          >
            {t('cancel')}
          </Button>
          <Button
            type="button"
            variant={action === 'disable' ? 'destructive' : 'default'}
            disabled={busy || !versionAvailable}
            onClick={() => void submit()}
          >
            {pending ? <Spinner aria-label={t('usersStatePending')} /> : null}
            {t(meta.confirm)}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
