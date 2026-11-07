import {
  Alert,
  Button,
  Chip,
  Modal,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { DataTable, type DataTableColumn } from '@identity/ui/data-table'
import { Plus } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { CopyButton } from '#/components/copy-button'
import { DatePickerField } from '#/components/date-picker-field'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleClientCredentialsDocument,
  type ClientCredentialKind,
  type ConsoleClientCredentialsQuery,
  type ConsoleClientCredentialsQueryVariables,
} from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  UserSelectField,
  UserTextAreaField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import { useClientDetail } from '../components/client-detail-shell'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  isCertificatePem,
  keyExpiryInstant,
  MAX_ACTIVE_CREDENTIALS,
  maskedSecretHint,
  shortHint,
} from '../lib/client-form'

type Credential = NonNullable<
  ConsoleClientCredentialsQuery['client']
>['credentials'][number]

const LIFETIMES = [30, 90, 180, 365, 730] as const

interface CredentialSection {
  kind: ClientCredentialKind
  label: MessageKey
  description: MessageKey
  empty: MessageKey
  column: MessageKey
}

const SECTIONS: readonly CredentialSection[] = [
  {
    kind: 'CLIENT_SECRET',
    label: 'clientsCredentialSecret',
    description: 'clientsSecretsDescription',
    empty: 'clientsSecretsEmpty',
    column: 'clientsCredentialColumnSecret',
  },
  {
    kind: 'PUBLIC_KEY',
    label: 'clientsCredentialPublicKey',
    description: 'clientsPublicKeysDescription',
    empty: 'clientsPublicKeysEmpty',
    column: 'clientsCredentialColumnThumbprint',
  },
  {
    kind: 'JWKS_URI',
    label: 'clientsCredentialJwks',
    description: 'clientsJwksDescription',
    empty: 'clientsJwksEmpty',
    column: 'clientsCredentialColumnJwksUri',
  },
]

interface IssuedSecret {
  secret: string
  expiresAt: string | null | undefined
}

/** What a credential row shows to identify the credential. */
function credentialLabel(credential: Credential): string {
  return credential.type === 'CLIENT_SECRET'
    ? maskedSecretHint(credential.hint)
    : credential.type === 'PUBLIC_KEY'
      ? shortHint(credential.hint)
      : credential.hint
}

function CredentialStatus({ credential }: { credential: Credential }) {
  const t = useTranslator()
  const [key, color] = credential.active
    ? (['clientsCredentialActive', 'success'] as const)
    : (['clientsCredentialExpired', 'warning'] as const)
  return (
    <Chip size="sm" variant="soft" color={color}>
      <Chip.Label>{t(key)}</Chip.Label>
    </Chip>
  )
}

function feedbackFrom(
  result: {
    errors: RbacFeedbackState['errors']
    failure?: RbacFeedbackState['failure'] | null
    stepUp?: RbacFeedbackState['stepUp']
    requestId?: string
    traceId?: string
    forbidden: boolean
  },
  code: string,
): RbacFeedbackState {
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

export function ClientCredentialsPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const detail = useClientDetail()
  const { clientId, scope } = detail
  const mutations = useClientMutations()
  const variables = useMemo(
    () => (scope.credentialsRead ? { id: clientId } : null),
    [clientId, scope.credentialsRead],
  )
  const query = useConsoleQuery<
    ConsoleClientCredentialsQuery,
    ConsoleClientCredentialsQueryVariables
  >(
    ConsoleClientCredentialsDocument,
    variables,
    Boolean(variables),
    'missing_client_credentials',
  )
  const client = query.data?.client ?? null
  const [lifetime, setLifetime] = useState('365')
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [issued, setIssued] = useState<IssuedSecret | null>(null)
  const [target, setTarget] = useState<{
    credential: Credential
    action: 'rotate' | 'revoke'
  } | null>(null)
  const revealDialog = useOverlayState({
    onOpenChange: (open) => {
      if (!open) setIssued(null)
    },
  })
  const confirmDialog = useOverlayState()
  const publicKeyDialog = useOverlayState()
  const jwksDialog = useOverlayState()

  if (!scope.credentialsRead && !detail.permissionsPending) {
    return (
      <RbacAccessRestricted
        title="clientsCredentialsNoReadTitle"
        description="clientsCredentialsNoReadDescription"
        onBack={() => void detail.query.refresh()}
        backLabel="clientsReload"
      />
    )
  }
  if (query.status === 'error') {
    return (
      <AsyncState
        kind={query.forbidden ? 'forbidden' : 'error'}
        title={t(failureTitleKey(query.failure, query.forbidden))}
        description={t(failureDescriptionKey(query.failure, query.forbidden))}
        requestId={query.requestId}
        traceId={query.traceId}
        issues={query.errors}
        onRetry={() => void query.refresh()}
      />
    )
  }

  const builtIn = detail.client?.builtIn ?? false
  const canAdd = scope.secretCreate && !builtIn && Boolean(client)
  const refreshAll = () => {
    void query.refresh()
    void detail.query.refresh()
  }

  async function issue(replaces?: Credential) {
    if (!client) return
    setPending(true)
    setFeedback(null)
    try {
      const base = {
        clientId,
        expectedVersion: client.version,
        lifetimeDays: Number(lifetime),
      }
      let payload:
        | Awaited<ReturnType<typeof mutations.createSecret>>
        | Awaited<ReturnType<typeof mutations.rotateSecret>>
      let data:
        | { secret: string; credential: { expiresAt?: string | null } }
        | undefined
      if (replaces) {
        const rotated = await mutations.rotateSecret({ ...base, credentialId: replaces.id })
        payload = rotated
        data = rotated.data?.rotateClientSecret
      } else {
        const created = await mutations.createSecret(base)
        payload = created
        data = created.data?.createClientSecret
      }
      if (!data) {
        setFeedback(feedbackFrom(payload, 'missing_client_secret_payload'))
        confirmDialog.close()
        return
      }
      confirmDialog.close()
      setIssued({ secret: data.secret, expiresAt: data.credential.expiresAt })
      revealDialog.open()
      refreshAll()
    } finally {
      setPending(false)
    }
  }

  async function revoke(credential: Credential) {
    if (!client) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.revokeCredential({
        clientId,
        credentialId: credential.id,
        expectedVersion: client.version,
      })
      confirmDialog.close()
      if (!result.data?.revokeClientCredential) {
        setFeedback(feedbackFrom(result, 'missing_revoke_credential_payload'))
        return
      }
      toast.success(t('clientsCredentialRevokedToast'))
      refreshAll()
    } finally {
      setPending(false)
    }
  }

  const credentials = client?.credentials ?? []
  const loading = query.status === 'idle' || query.status === 'loading'
  // The server lists credentials that are not revoked; expired ones stay as a
  // prompt to issue a replacement.
  const ofKind = (kind: ClientCredentialKind) =>
    credentials.filter((credential) => credential.type === kind)

  function rowActions(credential: Credential) {
    if (builtIn) return []
    return [
      ...(credential.type === 'CLIENT_SECRET' && scope.secretRotate
        ? [
            {
              id: 'rotate',
              label: t('clientsSecretRotate'),
              onAction: () => {
                setTarget({ credential, action: 'rotate' })
                confirmDialog.open()
              },
            },
          ]
        : []),
      ...(scope.credentialRevoke
        ? [
            {
              id: 'revoke',
              label: t('clientsCredentialRevoke'),
              danger: true,
              onAction: () => {
                setTarget({ credential, action: 'revoke' })
                confirmDialog.open()
              },
            },
          ]
        : []),
    ]
  }

  const activeCount = (kind: ClientCredentialKind) =>
    ofKind(kind).filter((credential) => credential.active).length
  const atLimit = (kind: ClientCredentialKind) =>
    activeCount(kind) >= MAX_ACTIVE_CREDENTIALS[kind]

  function sectionAction(kind: ClientCredentialKind): ReactNode {
    if (!canAdd) return null
    const full = atLimit(kind)
    if (kind === 'CLIENT_SECRET') {
      return (
        <div className="flex flex-wrap items-stretch gap-2">
          <div className="w-32">
            <UserSelectField
              name="secret-lifetime"
              label={t('clientsSecretLifetime')}
              hideLabel
              size="sm"
              value={lifetime}
              onChange={setLifetime}
              options={LIFETIMES.map((days) => ({
                id: String(days),
                label: t('clientsSecretLifetimeDays', { days }),
              }))}
              isDisabled={pending || full}
            />
          </div>
          {/* Stretch to the select's height so the pair lines up exactly. */}
          <Button
            size="sm"
            className="h-auto"
            isDisabled={pending || full}
            onPress={() => void issue()}
          >
            {pending && !target ? (
              <Spinner size="sm" aria-label={t('working')} />
            ) : (
              <Plus className="size-4" aria-hidden="true" />
            )}
            {t('clientsSecretCreate')}
          </Button>
        </div>
      )
    }
    return (
      <Button
        size="sm"
        isDisabled={pending || full}
        onPress={kind === 'PUBLIC_KEY' ? publicKeyDialog.open : jwksDialog.open}
      >
        <Plus className="size-4" aria-hidden="true" />
        {t(kind === 'PUBLIC_KEY' ? 'clientsPublicKeyAdd' : 'clientsJwksAdd')}
      </Button>
    )
  }

  function credentialTable(current: CredentialSection) {
    const rows = ofKind(current.kind)
    const jwks = current.kind === 'JWKS_URI'
    const columns: DataTableColumn[] = [
      { id: 'credential', label: t(current.column), primary: true },
      { id: 'status', label: t('clientsStatus'), primary: false },
      { id: 'created', label: t('tableColumnCreated'), primary: false },
      ...(jwks ? [] : [{ id: 'expires', label: t('clientsCredentialExpires'), primary: false }]),
      { id: 'actions', label: t('clientsColumnActions'), primary: false },
    ]
    return (
      <DataTable
        label={t(current.label)}
        loading={loading || query.refreshing}
        loadingLabel={t('tableLoading')}
        loadingRows={2}
        minWidth={jwks ? 640 : 760}
        density="compact"
        columns={columns}
      >
        <DataTable.Body
          renderEmptyState={() => (
            <AsyncState kind="empty" compact title={t(current.empty)} />
          )}
        >
          {rows.map((credential) => {
            const actions = rowActions(credential)
            const label = credentialLabel(credential)
            return (
              <DataTable.Row key={credential.id} id={credential.id}>
                <DataTable.Cell>
                  <div className="flex min-w-0 items-center gap-1">
                    <code
                      className="min-w-0 break-all font-mono text-xs"
                      title={credential.type === 'CLIENT_SECRET' ? undefined : credential.hint}
                    >
                      {label}
                    </code>
                    {credential.type === 'CLIENT_SECRET' ? null : (
                      <CopyButton value={credential.hint} label={t(current.column)} />
                    )}
                  </div>
                </DataTable.Cell>
                <DataTable.Cell>
                  <CredentialStatus credential={credential} />
                </DataTable.Cell>
                <DataTable.Cell>
                  <span className="whitespace-nowrap text-sm">
                    {formatDateTime(credential.createdAt, locale, timeZone)}
                  </span>
                </DataTable.Cell>
                {jwks ? null : (
                  <DataTable.Cell>
                    <span className="whitespace-nowrap text-sm">
                      {credential.expiresAt
                        ? formatDateTime(credential.expiresAt, locale, timeZone)
                        : t('clientsCredentialNeverExpires')}
                    </span>
                  </DataTable.Cell>
                )}
                <DataTable.Cell>
                  {actions.length ? (
                    <TableRowActions subject={label} actions={actions} />
                  ) : null}
                </DataTable.Cell>
              </DataTable.Row>
            )
          })}
        </DataTable.Body>
      </DataTable>
    )
  }

  return (
    <div className="space-y-8">
      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={refreshAll}
          reloadPending={query.refreshing}
        />
      ) : null}
      {SECTIONS.map((entry) => (
        <section key={entry.kind} className="space-y-2">
          <header className="flex flex-col gap-3 px-1 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <h2 className="flex items-baseline gap-2 text-sm font-semibold">
                {t(entry.label)}
                <span className="text-xs font-normal tabular-nums text-muted">
                  {t('clientsCredentialUsage', {
                    used: activeCount(entry.kind),
                    max: MAX_ACTIVE_CREDENTIALS[entry.kind],
                  })}
                </span>
              </h2>
              <p className="mt-0.5 max-w-2xl text-xs leading-5 text-muted">
                {t(entry.description)}
              </p>
              {canAdd && atLimit(entry.kind) ? (
                <p className="text-xs leading-5 text-warning">
                  {t('clientsCredentialLimitReached')}
                </p>
              ) : null}
            </div>
            {sectionAction(entry.kind)}
          </header>
          {credentialTable(entry)}
        </section>
      ))}

      <ConfirmationDialog
        state={confirmDialog}
        title={t(
          target?.action === 'rotate' ? 'clientsSecretRotateTitle' : 'clientsCredentialRevokeTitle',
        )}
        description={t(
          target?.action === 'rotate'
            ? 'clientsSecretRotateDescription'
            : 'clientsCredentialRevokeDescription',
          { hint: target ? credentialLabel(target.credential) : '' },
        )}
        confirmLabel={t(
          target?.action === 'rotate' ? 'clientsSecretRotate' : 'clientsCredentialRevoke',
        )}
        destructive
        pending={pending}
        onConfirm={() => {
          if (!target) return
          void (target.action === 'rotate' ? issue(target.credential) : revoke(target.credential))
        }}
      />

      <Modal state={revealDialog}>
        <Modal.Backdrop isDismissable={false}>
          <Modal.Container size="md">
            <Modal.Dialog>
              {({ close }) => (
                <>
                  <Modal.Header>
                    <Modal.Heading>{t('clientsSecretIssuedTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body className="space-y-3">
                    <Alert status="warning">
                      <Alert.Indicator />
                      <Alert.Content>
                        <Alert.Description>{t('clientsSecretIssuedWarning')}</Alert.Description>
                      </Alert.Content>
                    </Alert>
                    {issued ? (
                      <>
                        <div className="flex items-start gap-1 rounded-field bg-surface-secondary p-3">
                          <code className="min-w-0 flex-1 break-all text-sm">{issued.secret}</code>
                          <CopyButton value={issued.secret} label={t('clientsSecret')} />
                        </div>
                        {issued.expiresAt ? (
                          <p className="text-xs text-muted">
                            {t('clientsSecretIssuedExpires', {
                              date: formatDateTime(issued.expiresAt, locale, timeZone),
                            })}
                          </p>
                        ) : null}
                      </>
                    ) : null}
                  </Modal.Body>
                  <Modal.Footer>
                    <Button onPress={close}>{t('clientsSecretStored')}</Button>
                  </Modal.Footer>
                </>
              )}
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>

      {/* Kept mounted while the credentials refetch so a draft survives. */}
      <>
          <AddPublicKeyDialog
            state={publicKeyDialog}
            onAdd={async (key, expiresAt) => {
              if (!client) return CLIENT_NOT_LOADED
              const result = await mutations.addPublicKey({
                clientId,
                expectedVersion: client.version,
                key,
                expiresAt,
              })
              if (result.data?.addClientPublicKey) refreshAll()
              return result.data?.addClientPublicKey ? null : result
            }}
          />
          <AddJwksUriDialog
            state={jwksDialog}
            onAdd={async (jwksUri) => {
              if (!client) return CLIENT_NOT_LOADED
              const result = await mutations.addJwksUri({
                clientId,
                expectedVersion: client.version,
                jwksUri,
              })
              if (result.data?.addClientJwksUri) refreshAll()
              return result.data?.addClientJwksUri ? null : result
            }}
          />
      </>
    </div>
  )
}

type OverlayState = ReturnType<typeof useOverlayState>

/** The credentials are still reloading; the dialog keeps its draft for a retry. */
const CLIENT_NOT_LOADED = {
  errors: [],
  failure: { kind: 'invalid_response', code: 'client_credentials_not_loaded' },
  forbidden: false,
} satisfies Parameters<typeof feedbackFrom>[0]

/** A failed add, or `null` when the credential was stored. */
type AddFailure = Parameters<typeof feedbackFrom>[0] | null

/**
 * One add-credential dialog. Field errors stay next to their field, other
 * failures (including a required step-up) render inside the dialog so the
 * pasted value survives a retry.
 */
function AddCredentialDialog({
  state,
  title,
  pending,
  feedback,
  onSubmit,
  onClosed,
  children,
}: {
  state: OverlayState
  title: string
  pending: boolean
  feedback: RbacFeedbackState | null
  onSubmit: () => void
  onClosed: () => void
  children: ReactNode
}) {
  const t = useTranslator()
  return (
    <Modal state={state}>
      <Modal.Backdrop isDismissable={!pending}>
        <Modal.Container size="lg">
          <Modal.Dialog>
            {({ close }) => (
              <form
                noValidate
                aria-busy={pending}
                onSubmit={(event) => {
                  event.preventDefault()
                  onSubmit()
                }}
              >
                <Modal.Header>
                  <Modal.Heading>{title}</Modal.Heading>
                </Modal.Header>
                <Modal.Body className="space-y-4">
                  {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
                  {children}
                </Modal.Body>
                <Modal.Footer>
                  <Button
                    variant="secondary"
                    isDisabled={pending}
                    onPress={() => {
                      close()
                      onClosed()
                    }}
                  >
                    {t('cancel')}
                  </Button>
                  <Button type="submit" isDisabled={pending}>
                    {pending ? <Spinner size="sm" aria-label={t('working')} /> : null}
                    {t('clientsCredentialAddSubmit')}
                  </Button>
                </Modal.Footer>
              </form>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}

function useAddCredential(state: OverlayState) {
  const t = useTranslator()
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  async function submit(run: () => Promise<AddFailure>, onDone: () => void) {
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const failure = await run()
      if (!failure) {
        toast.success(t('clientsCredentialAddedToast'))
        state.close()
        onDone()
        return
      }
      const fields = clientFieldErrors(failure.errors).text
      if (Object.keys(fields).length) {
        setFieldErrors(fields)
      } else {
        setFeedback(feedbackFrom(failure, 'missing_add_credential_payload'))
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_credential_add_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  return {
    pending,
    feedback,
    fieldErrors,
    setFieldErrors,
    submit,
    reset() {
      setFeedback(null)
      setFieldErrors({})
    },
  }
}

function AddPublicKeyDialog({
  state,
  onAdd,
}: {
  state: OverlayState
  onAdd: (key: string, expiresAt: string | null) => Promise<AddFailure>
}) {
  const t = useTranslator()
  const { timeZone } = useLocale()
  const add = useAddCredential(state)
  const [key, setKey] = useState('')
  const [expiry, setExpiry] = useState('')
  const certificate = isCertificatePem(key)

  function clear() {
    setKey('')
    setExpiry('')
    add.reset()
  }

  return (
    <AddCredentialDialog
      state={state}
      title={t('clientsPublicKeyAdd')}
      pending={add.pending}
      feedback={add.feedback}
      onClosed={clear}
      onSubmit={() => {
        const errors: Record<string, string> = {}
        if (!key.trim()) errors.key = t('clientsPublicKeyRequired')
        const expiresAt = certificate || !expiry ? null : keyExpiryInstant(expiry, timeZone)
        if (!certificate && !expiresAt) errors.expiresAt = t('clientsPublicKeyExpiryRequired')
        if (Object.keys(errors).length) {
          add.setFieldErrors(errors)
          return
        }
        void add.submit(() => onAdd(key.trim(), expiresAt), clear)
      }}
    >
      <UserTextAreaField
        name="public-key"
        label={t('clientsPublicKeyField')}
        description={t('clientsPublicKeyFieldHint')}
        placeholder="-----BEGIN PUBLIC KEY-----"
        value={key}
        onChange={(value) => {
          setKey(value)
          add.reset()
        }}
        rows={8}
        isRequired
        isDisabled={add.pending}
        error={add.fieldErrors.key}
      />
      {certificate ? (
        <p className="text-xs text-muted">{t('clientsPublicKeyCertificateExpiry')}</p>
      ) : (
        <DatePickerField
          name="public-key-expiry"
          label={t('clientsPublicKeyExpires')}
          description={t('clientsPublicKeyExpiresHint')}
          value={expiry}
          onChange={(value) => {
            setExpiry(value)
            add.reset()
          }}
          isRequired
          isDisabled={add.pending}
          error={add.fieldErrors.expiresAt}
        />
      )}
    </AddCredentialDialog>
  )
}

function AddJwksUriDialog({
  state,
  onAdd,
}: {
  state: OverlayState
  onAdd: (jwksUri: string) => Promise<AddFailure>
}) {
  const t = useTranslator()
  const add = useAddCredential(state)
  const [uri, setUri] = useState('')

  function clear() {
    setUri('')
    add.reset()
  }

  return (
    <AddCredentialDialog
      state={state}
      title={t('clientsJwksAdd')}
      pending={add.pending}
      feedback={add.feedback}
      onClosed={clear}
      onSubmit={() => {
        if (!uri.trim()) {
          add.setFieldErrors({ jwksUri: t('clientsJwksRequired') })
          return
        }
        void add.submit(() => onAdd(uri.trim()), clear)
      }}
    >
      <UserTextField
        name="jwks-uri"
        label={t('clientsJwksField')}
        description={t('clientsJwksFieldHint')}
        type="url"
        placeholder="https://client.example.com/.well-known/jwks.json"
        value={uri}
        onChange={(value) => {
          setUri(value)
          add.reset()
        }}
        isRequired
        isDisabled={add.pending}
        error={add.fieldErrors.jwksUri}
      />
    </AddCredentialDialog>
  )
}
