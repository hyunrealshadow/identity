import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Spinner } from '@identity/ui/components/spinner'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useNavigate } from '@tanstack/react-router'
import { Plus } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { CopyButton } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { ResourceTable, type ResourceColumn } from '#/components/resource-table'
import { TableRowActions, type TableRowAction } from '#/components/table-row-actions'
import {
  ConsoleJwksUriDocument,
  ConsoleKeysDocument,
  ConsoleSigningKeyAlgorithmsDocument,
  type ConsoleJwksUriQuery,
  type ConsoleJwksUriQueryVariables,
  type ConsoleKeysQuery,
  type ConsoleKeysQueryVariables,
  type ConsoleSigningKeyAlgorithmsQuery,
  type ConsoleSigningKeyAlgorithmsQueryVariables,
  type KeyUse,
} from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import { failureDescriptionKey, failureTitleKey } from '#/lib/graphql/presentation'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'
import { useInstanceSettings } from '../../settings/components/settings-shell'
import { mutationFeedback, networkFeedback } from '../../settings/lib/feedback'
import { KeyStatusChip } from '../components/key-status'
import { useKeyMutations } from '../hooks/key-mutations'
import { AlgorithmSelect, optionId } from '../components/algorithm-select'
import { KEYS_PAGE_SIZE, keysQueryVariables, type KeysSearch } from '../lib/keys-search'

const noVariables = {}

/** Compact keys that every client library verifies. */
const DEFAULT_SIGNING_KEY_OPTION = 'ES256:ECDSA_P256'

type ManagedKey = NonNullable<ConsoleKeysQuery['keys']>['edges'][number]['node']
type Action = 'rotate' | 'rotateAndRevoke' | 'revoke'

/** Copy that differs between signing and encryption keys. */
const COPY: Record<
  KeyUse,
  {
    path: '/settings/signing-keys' | '/settings/encryption-keys'
    title: MessageKey
    description: MessageKey
    listHint: MessageKey
    rotateDescription: MessageKey
    rotateAndRevokeDescription: MessageKey
    revokeDescription: MessageKey
  }
> = {
  SIGNING: {
    path: '/settings/signing-keys',
    title: 'keysSigningTitle',
    description: 'keysSigningDescription',
    listHint: 'keysSigningListHint',
    rotateDescription: 'keysRotateSigningHint',
    rotateAndRevokeDescription: 'keysRotateAndRevokeSigningHint',
    revokeDescription: 'keysRevokeSigningDescription',
  },
  ENCRYPTION: {
    path: '/settings/encryption-keys',
    title: 'keysEncryptionTitle',
    description: 'keysEncryptionDescription',
    listHint: 'keysEncryptionListHint',
    rotateDescription: 'keysRotateEncryptionHint',
    rotateAndRevokeDescription: 'keysRotateAndRevokeEncryptionHint',
    revokeDescription: 'keysRevokeEncryptionDescription',
  },
}

export function KeysSettingsPage({ use, search }: { use: KeyUse; search: KeysSearch }) {
  const navigate = useNavigate()
  const { keys: scope, permissionsPending } = useInstanceSettings()
  if (!scope.read && !permissionsPending) {
    return (
      <RbacAccessRestricted
        title="keysNoReadTitle"
        description="keysNoReadDescription"
        onBack={() => void navigate({ to: '/' })}
        backLabel="goHome"
      />
    )
  }
  // Keyed by use so switching tabs never carries a dialog or feedback over.
  return <KeysSection key={use} use={use} search={search} />
}

function KeysSection({ use, search }: { use: KeyUse; search: KeysSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const { keys: scope } = useInstanceSettings()
  const copy = COPY[use]
  const mutations = useKeyMutations()
  const confirmDialog = useOverlayState()
  const createDialog = useOverlayState()
  const [target, setTarget] = useState<{ action: Action; key: ManagedKey } | null>(null)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)

  const listVariables = useMemo(
    () => (scope.read ? keysQueryVariables(use, search) : null),
    [scope.read, use, search.show, search.size, search.after, search.before],
  )
  const list = useConsoleQuery<ConsoleKeysQuery, ConsoleKeysQueryVariables>(
    ConsoleKeysDocument,
    listVariables,
    Boolean(listVariables),
    'missing_key_connection',
    { keepPreviousData: true },
  )
  const signing = use === 'SIGNING'
  const jwks = useConsoleQuery<ConsoleJwksUriQuery, ConsoleJwksUriQueryVariables>(
    ConsoleJwksUriDocument,
    signing ? {} : null,
    signing,
    'missing_instance_metadata',
  )
  const jwksUri = jwks.data?.instanceMetadata.jwksUri
  const connection = list.data?.keys
  const pager = useCursorPagination({
    search,
    variables: listVariables,
    onNavigate: (cursor) =>
      void navigate({
        to: copy.path,
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
  })

  function refresh() {
    void list.refresh()
  }

  function ask(action: Action, key: ManagedKey) {
    setFeedback(null)
    setTarget({ action, key })
    confirmDialog.open()
  }

  async function confirm() {
    if (!target || pending) return
    const { action, key } = target
    setPending(true)
    try {
      let result: Parameters<typeof mutationFeedback>[0]
      let done: boolean
      if (action === 'rotate') {
        const response = await mutations.rotate(key.id)
        result = response
        done = Boolean(response.data?.rotateKey)
      } else if (action === 'rotateAndRevoke') {
        const response = await mutations.rotateAndRevoke(key.id)
        result = response
        done = Boolean(response.data?.rotateAndRevokeKey)
      } else {
        const response = await mutations.revoke(key.id)
        result = response
        done = Boolean(response.data?.revokeKey)
      }
      if (!done) {
        setFeedback(mutationFeedback(result, `missing_${action}_key_payload`))
        return
      }
      toast.success(
        t(
          action === 'rotate'
            ? 'keysRotatedToast'
            : action === 'rotateAndRevoke'
              ? 'keysRotatedAndRevokedToast'
              : 'keysRevokedToast',
        ),
      )
    } catch {
      setFeedback(networkFeedback(`${action}_key_request_failed`))
    } finally {
      confirmDialog.close()
      setPending(false)
    }
  }

  const items = (connection?.edges ?? []).map(({ node }) => node)
  // Revoking a key in use needs another active key of the same use. The
  // server enforces this; the listed keys only decide whether to offer it.
  const activeCount = items.filter((key) => key.status === 'ACTIVE').length

  function rowActions(key: ManagedKey): TableRowAction[] {
    const actions: TableRowAction[] = []
    if (key.status === 'ACTIVE') {
      if (scope.rotate) {
        actions.push({ id: 'rotate', label: t('keysRotate'), onAction: () => ask('rotate', key) })
      }
      if (scope.rotateAndRevoke) {
        actions.push({
          id: 'rotateAndRevoke',
          label: t('keysRotateAndRevoke'),
          danger: true,
          onAction: () => ask('rotateAndRevoke', key),
        })
      }
      if (scope.revoke && activeCount > 1) {
        actions.push({
          id: 'revoke',
          label: t('keysRevoke'),
          danger: true,
          onAction: () => ask('revoke', key),
        })
      }
    } else if (scope.revoke && (key.status === 'RETIRED' || key.status === 'EXPIRED')) {
      actions.push({
        id: 'revoke',
        label: t('keysRevoke'),
        danger: true,
        onAction: () => ask('revoke', key),
      })
    }
    return actions
  }

  const columns: ResourceColumn<ManagedKey>[] = [
    {
      id: 'status',
      label: t('keysColumnStatus'),
      render: (key) => <KeyStatusChip use={use} status={key.status} inUse={key.inUse} />,
    },
    {
      id: 'keyId',
      label: t('keysColumnKeyId'),
      primary: true,
      render: (key) => (
        <div className="flex min-w-0 items-center gap-1">
          <code className="break-all rounded-md bg-muted px-1.5 py-0.5 text-xs">{key.keyId}</code>
          <CopyButton value={key.keyId} label={t('keysColumnKeyId')} />
        </div>
      ),
    },
    {
      id: 'algorithm',
      label: t('keysColumnAlgorithm'),
      // A signing key leads with its signing algorithm; encryption bindings
      // it also publishes are counted.
      render: (key) => (
        <span className="whitespace-nowrap text-sm" title={key.algorithms.join(', ')}>
          {key.algorithms[0]}
          {key.algorithms.length > 1 ? (
            <span className="ml-1.5 text-xs text-muted-foreground">
              {t('keysMoreAlgorithms', { count: key.algorithms.length - 1 })}
            </span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'created',
      label: t('tableColumnCreated'),
      render: (key) => (
        <span className="whitespace-nowrap text-sm">
          {formatDateTime(key.createdAt, locale, timeZone)}
        </span>
      ),
    },
    {
      id: 'expires',
      label: t('keysColumnExpires'),
      render: (key) => (
        <span className="whitespace-nowrap text-sm">
          {formatDateTime(key.expiresAt, locale, timeZone)}
        </span>
      ),
    },
  ]
  // The column only appears when some row can be acted on. While rows load,
  // the permissions decide, so the header does not change when they arrive.
  const canAct = scope.rotate || scope.rotateAndRevoke || scope.revoke
  const hasActions = connection
    ? items.some((key) => rowActions(key).length > 0)
    : canAct
  if (hasActions) {
    columns.push({
      id: 'actions',
      label: t('keysColumnActions'),
      render: (key) => <TableRowActions subject={key.keyId} actions={rowActions(key)} />,
    })
  }

  const dialogText: Record<Action, { title: MessageKey; description: MessageKey; confirm: MessageKey }> = {
    rotate: { title: 'keysRotateTitle', description: copy.rotateDescription, confirm: 'keysRotate' },
    rotateAndRevoke: {
      title: 'keysRotateAndRevokeTitle',
      description: copy.rotateAndRevokeDescription,
      confirm: 'keysRotateAndRevoke',
    },
    revoke: { title: 'keysRevokeTitle', description: copy.revokeDescription, confirm: 'keysRevoke' },
  }
  const text = dialogText[target?.action ?? 'rotate']

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold tracking-tight">{t(copy.title)}</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">
            {t(copy.description)}
          </p>
        </div>
        {signing && scope.create ? (
          <Button
            className="shrink-0"
            onClick={() => {
              setFeedback(null)
              createDialog.open()
            }}
          >
            <Plus className="size-4" aria-hidden="true" />
            {t('keysAddSigning')}
          </Button>
        ) : null}
      </div>

      {feedback ? (
        <RbacMutationFeedback feedback={feedback} onReload={refresh} reloadPending={list.refreshing} />
      ) : null}

      <section className="space-y-3">
        <div className="px-1">
          <p className="text-xs leading-5 text-muted-foreground">{t(copy.listHint)}</p>
          {signing ? (
            // Fixed height, so the table does not move when the address arrives.
            <div className="mt-1.5 flex h-7 min-w-0 items-center gap-1">
              <span className="text-xs text-muted-foreground">{t('keysJwksUri')}</span>
              {jwksUri ? (
                <>
                  <code className="truncate rounded-md bg-muted px-1.5 py-0.5 text-xs">{jwksUri}</code>
                  <CopyButton value={jwksUri} label={t('keysJwksUri')} />
                </>
              ) : (
                <Skeleton className="h-5 w-72 rounded-md" />
              )}
            </div>
          ) : null}
        </div>
        <ResourceTable
          id={`keys-${use.toLowerCase()}`}
          label={t(copy.title)}
          filters={
            <div className="w-44">
              <UserSelectField
                name="key-visibility"
                label={t('keysShow')}
                hideLabel
                value={search.show ?? 'valid'}
                onChange={(value) =>
                  void navigate({
                    to: copy.path,
                    search: { show: value === 'all' ? 'all' : undefined, size: search.size },
                  })
                }
                options={[
                  { id: 'valid', label: t('keysShowValid') },
                  { id: 'all', label: t('keysShowAll') },
                ]}
              />
            </div>
          }
          items={items}
          onOrderChange={() => undefined}
          onRefresh={refresh}
          refreshing={list.refreshing || list.status === 'loading'}
          emptyState={
            list.status === 'error' ? (
              <AsyncState
                kind={list.forbidden ? 'forbidden' : 'error'}
                title={t(failureTitleKey(list.failure, list.forbidden))}
                description={t(failureDescriptionKey(list.failure, list.forbidden))}
                requestId={list.requestId}
                traceId={list.traceId}
                issues={list.errors}
                onRetry={() => void list.refresh()}
              />
            ) : (
              <AsyncState kind="empty" compact title={t('keysEmpty')} />
            )
          }
          pagination={
            connection ? (
              <CursorPagination
                label={t(copy.title)}
                pageCount={connection.edges.length}
                totalCount={connection.totalCount}
                pageInfo={connection.pageInfo}
                controller={pager}
                isDisabled={list.refreshing}
                pageSize={search.size ?? KEYS_PAGE_SIZE}
                onPageSizeChange={(size) =>
                  void navigate({
                    to: copy.path,
                    search: { ...search, size, after: undefined, before: undefined },
                  })
                }
              />
            ) : null
          }
          columns={columns}
        />
      </section>

      {/* Dialogs stay mounted outside the row menu so closing it keeps them. */}
      <ConfirmationDialog
        state={confirmDialog}
        title={t(text.title)}
        description={t(text.description)}
        confirmLabel={t(text.confirm)}
        destructive={target?.action !== 'rotate'}
        pending={pending}
        onConfirm={() => void confirm()}
      >
        {target ? (
          <code className="break-all rounded-md bg-muted px-1.5 py-0.5 text-xs">
            {target.key.keyId}
          </code>
        ) : null}
      </ConfirmationDialog>
      {signing && scope.create ? (
        <AddSigningKeyDialog
          state={createDialog}
          onCreated={() => {
            refresh()
            toast.success(t('keysAddedToast'))
          }}
        />
      ) : null}
    </div>
  )
}

function AddSigningKeyDialog({
  state,
  onCreated,
}: {
  state: ReturnType<typeof useOverlayState>
  onCreated: () => void
}) {
  const t = useTranslator()
  const mutations = useKeyMutations()
  // Loaded with the page, so the dialog opens with its options ready.
  const algorithms = useConsoleQuery<
    ConsoleSigningKeyAlgorithmsQuery,
    ConsoleSigningKeyAlgorithmsQueryVariables
  >(ConsoleSigningKeyAlgorithmsDocument, noVariables, true, 'missing_signing_key_algorithms')
  const options = algorithms.data?.signingKeyAlgorithms ?? []
  const [choice, setChoice] = useState(DEFAULT_SIGNING_KEY_OPTION)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const selected =
    options.find((option) => optionId(option) === choice) ?? options[0] ?? null

  async function submit() {
    if (pending || !selected) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.createSigning(selected.algorithm, selected.keyAlgorithm)
      if (!result.data?.createSigningKey) {
        setFeedback(mutationFeedback(result, 'missing_create_signing_key_payload'))
        return
      }
      state.close()
      onCreated()
    } catch {
      setFeedback(networkFeedback('create_signing_key_request_failed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog
      open={state.isOpen}
      onOpenChange={(open) => {
        if (!open && pending) return
        state.setOpen(open)
        if (!open) setFeedback(null)
      }}
    >
      <DialogContent showCloseButton={!pending} closeLabel={t('close')}>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            void submit()
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('keysAddSigningTitle')}</DialogTitle>
            <DialogDescription>{t('keysAddSigningDescription')}</DialogDescription>
          </DialogHeader>
          {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
          <AlgorithmSelect
            label={t('keysSigningAlgorithm')}
            value={selected ? optionId(selected) : ''}
            onChange={(option) => setChoice(optionId(option))}
            isDisabled={pending || options.length === 0}
            options={options}
          />
          <DialogFooter>
            <Button type="button" variant="outline" disabled={pending} onClick={() => state.close()}>
              {t('tableCancel')}
            </Button>
            <Button type="submit" disabled={pending || !selected}>
              {pending ? <Spinner aria-label={t('keysAddPending')} /> : <Plus className="size-4" aria-hidden="true" />}
              {t('keysAdd')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
