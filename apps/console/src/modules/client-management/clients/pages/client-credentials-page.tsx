import {
  Alert,
  Button,
  Chip,
  Modal,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { DataTable } from '@identity/ui/data-table'
import { KeyRound, Plus } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { CopyButton } from '#/components/copy-button'
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
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'
import { useClientDetail } from '../components/client-detail-shell'
import { useClientMutations } from '../hooks/client-mutations'
import { usesClientSecret } from '../lib/client-form'

type Credential = NonNullable<
  ConsoleClientCredentialsQuery['client']
>['credentials'][number]

const KIND_LABELS: Record<ClientCredentialKind, MessageKey> = {
  CLIENT_SECRET: 'clientsCredentialSecret',
  PUBLIC_KEY: 'clientsCredentialPublicKey',
  JWKS_URI: 'clientsCredentialJwks',
}

const LIFETIMES = [30, 90, 180, 365, 730] as const

interface IssuedSecret {
  secret: string
  hint: string
  expiresAt: string
}

function CredentialStatus({ credential }: { credential: Credential }) {
  const t = useTranslator()
  const [key, color] = credential.revokedAt
    ? (['clientsCredentialRevoked', 'default'] as const)
    : credential.active
      ? (['clientsCredentialActive', 'success'] as const)
      : (['clientsCredentialExpired', 'warning'] as const)
  return (
    <Chip size="sm" variant="soft" color={color}>
      <Chip.Label>{t(key)}</Chip.Label>
    </Chip>
  )
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
  const [target, setTarget] = useState<{ credential: Credential; action: 'rotate' | 'revoke' } | null>(null)
  const revealDialog = useOverlayState({
    onOpenChange: (open) => {
      if (!open) setIssued(null)
    },
  })
  const confirmDialog = useOverlayState()

  if (!scope.credentialsRead) {
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
  const secretMethod = client ? usesClientSecret(client.tokenEndpointAuthMethod) : false
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
      let payload: Awaited<ReturnType<typeof mutations.createSecret>> | Awaited<ReturnType<typeof mutations.rotateSecret>>
      let data: { secret: string; credential: { hint: string; expiresAt: string } } | undefined
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
        setFeedback({
          errors: payload.errors,
          failure: payload.failure ?? {
            kind: 'invalid_response',
            code: 'missing_client_secret_payload',
            requestId: payload.requestId,
            traceId: payload.traceId,
          },
          stepUp: payload.stepUp,
          requestId: payload.requestId,
          traceId: payload.traceId,
          forbidden: payload.forbidden,
        })
        return
      }
      confirmDialog.close()
      setIssued({
        secret: data.secret,
        hint: data.credential.hint,
        expiresAt: data.credential.expiresAt,
      })
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
      if (!result.data?.revokeClientCredential) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_revoke_credential_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        confirmDialog.close()
        return
      }
      confirmDialog.close()
      toast.success(t('clientsCredentialRevokedToast'))
      refreshAll()
    } finally {
      setPending(false)
    }
  }

  const credentials = client?.credentials ?? []
  const loading = query.status === 'idle' || query.status === 'loading'

  return (
    <div className="space-y-4">
      {client && !secretMethod ? (
        <Alert status="default">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('clientsNoSecretTitle')}</Alert.Title>
            <Alert.Description>{t('clientsNoSecretDescription')}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={refreshAll}
          reloadPending={query.refreshing}
        />
      ) : null}
      <section className="space-y-4">
        <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-base font-semibold">{t('clientsCredentialsTitle')}</h2>
            <p className="mt-1 text-sm text-muted">{t('clientsCredentialsDescription')}</p>
          </div>
          {secretMethod && scope.secretCreate && !builtIn ? (
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-36">
                <UserSelectField
                  name="secret-lifetime"
                  label={t('clientsSecretLifetime')}
                  value={lifetime}
                  onChange={setLifetime}
                  options={LIFETIMES.map((days) => ({
                    id: String(days),
                    label: t('clientsSecretLifetimeDays', { days }),
                  }))}
                  isDisabled={pending}
                />
              </div>
              <Button isDisabled={pending || !client} onPress={() => void issue()}>
                {pending && !target ? (
                  <Spinner size="sm" aria-label={t('working')} />
                ) : (
                  <Plus className="size-4" aria-hidden="true" />
                )}
                {t('clientsSecretCreate')}
              </Button>
            </div>
          ) : null}
        </header>
        <DataTable
          label={t('clientsCredentialsTitle')}
          loading={loading || query.refreshing}
          loadingLabel={t('tableLoading')}
          minWidth={760}
          columns={[
            { id: 'type', label: t('clientsCredentialType'), primary: true },
            { id: 'status', label: t('clientsStatus'), primary: false },
            { id: 'created', label: t('tableColumnCreated'), primary: false },
            { id: 'expires', label: t('clientsCredentialExpires'), primary: false },
            { id: 'actions', label: t('clientsColumnActions'), primary: false },
          ]}
        >
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState kind="empty" compact title={t('clientsCredentialsEmpty')} />
            )}
          >
            {credentials.map((credential) => {
              const usable = !credential.revokedAt
              const secret = credential.type === 'CLIENT_SECRET'
              const actions = [
                ...(usable && secret && scope.secretRotate && !builtIn
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
                ...(usable && scope.credentialRevoke && !builtIn
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
              return (
                <DataTable.Row key={credential.id} id={credential.id}>
                  <DataTable.Cell>
                    <div className="flex items-center gap-2">
                      <KeyRound className="size-4 text-muted" aria-hidden="true" />
                      <span className="font-medium">{t(KIND_LABELS[credential.type])}</span>
                      <code className="text-xs text-muted">{credential.hint}</code>
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
                  <DataTable.Cell>
                    <span className="whitespace-nowrap text-sm">
                      {credential.revokedAt
                        ? t('clientsCredentialRevokedAt', {
                            date: formatDateTime(credential.revokedAt, locale, timeZone),
                          })
                        : formatDateTime(credential.expiresAt, locale, timeZone)}
                    </span>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    {actions.length ? (
                      <TableRowActions subject={credential.hint} actions={actions} />
                    ) : null}
                  </DataTable.Cell>
                </DataTable.Row>
              )
            })}
          </DataTable.Body>
        </DataTable>
      </section>

      <ConfirmationDialog
        state={confirmDialog}
        title={t(
          target?.action === 'rotate' ? 'clientsSecretRotateTitle' : 'clientsCredentialRevokeTitle',
        )}
        description={t(
          target?.action === 'rotate'
            ? 'clientsSecretRotateDescription'
            : 'clientsCredentialRevokeDescription',
          { hint: target?.credential.hint ?? '' },
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
                        <p className="text-xs text-muted">
                          {t('clientsSecretIssuedExpires', {
                            date: formatDateTime(issued.expiresAt, locale, timeZone),
                          })}
                        </p>
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
    </div>
  )
}
