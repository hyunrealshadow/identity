import { Alert, Button, Chip, Spinner, Switch, toast } from '@heroui/react'
import { DataTable } from '@identity/ui/data-table'
import { Save } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleClientScopesDocument,
  type ConsoleClientScopesQuery,
  type ConsoleClientScopesQueryVariables,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { PermissionPickerDialog } from '#/modules/user-management/roles/components/permission-picker-dialog'
import type { StagedPermission } from '#/modules/user-management/roles/lib/permission-selection'
import { useClientDetail } from '../components/client-detail-shell'
import { useClientMutations } from '../hooks/client-mutations'

/** One page covers every realistic client; larger sets are read-only here. */
const PAGE_SIZE = 100

interface ScopeRow {
  id: string
  code: string
  name: string
  names: ReadonlyArray<{ locale: string; value: string }>
  /** `null` marks a protocol scope, which this page does not replace. */
  resourceId: string | null
  clientGranted: boolean
}

function rowsFrom(data: ConsoleClientScopesQuery | null): ScopeRow[] {
  return (data?.client?.scopes.edges ?? []).map((edge) => ({
    id: edge.node.id,
    code: edge.node.code,
    name: edge.node.name,
    names: edge.node.names,
    resourceId: edge.node.resourceId ?? null,
    clientGranted: edge.clientGranted,
  }))
}

export function ClientScopesPage() {
  const t = useTranslator()
  const { locale } = useLocale()
  const workspace = useWorkspace()
  const rbac = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const detail = useClientDetail()
  const { clientId, scope } = detail
  const mutations = useClientMutations()
  const variables = useMemo<ConsoleClientScopesQueryVariables>(
    () => ({ id: clientId, orderBy: 'CODE_ASC', first: PAGE_SIZE }),
    [clientId],
  )
  const query = useConsoleQuery<ConsoleClientScopesQuery, ConsoleClientScopesQueryVariables>(
    ConsoleClientScopesDocument,
    variables,
    'ConsoleClientScopes',
    true,
    'missing_client_scopes',
  )
  const server = useMemo(() => rowsFrom(query.data), [query.data])
  const [rows, setRows] = useState<ScopeRow[]>([])
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  useEffect(() => setRows(server), [server])

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

  const client = query.data?.client ?? null
  const complete = client ? !client.scopes.pageInfo.hasNextPage : false
  const editable =
    scope.scopesWrite && !detail.client?.builtIn && complete && Boolean(client)
  const signature = (list: ScopeRow[]) =>
    JSON.stringify(
      list
        .filter((row) => row.resourceId)
        .map((row) => [row.id, row.clientGranted])
        .sort(),
    )
  const dirty = signature(rows) !== signature(server)
  const assignedIds = new Set(rows.map((row) => row.id))
  const displayName = detail.client
    ? (resolveLocalizedText(detail.client.names, locale) ?? detail.client.name)
    : ''

  function addScopes(metadata: StagedPermission[]) {
    setFeedback(null)
    setRows((current) => [
      ...current,
      ...metadata
        .filter((entry) => !current.some((row) => row.id === entry.id))
        .map((entry) => ({
          id: entry.id,
          code: entry.code,
          name: entry.name ?? entry.code,
          names: entry.names ?? [],
          resourceId: entry.resourceId,
          clientGranted: false,
        })),
    ])
  }

  async function save() {
    if (!client || pending) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.setScopes({
        clientId,
        expectedVersion: client.version,
        scopes: rows
          .filter((row) => row.resourceId)
          .map((row) => ({ scopeId: row.id, clientGranted: row.clientGranted })),
      })
      if (!result.data?.setClientScopes) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_set_client_scopes_payload',
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
      toast.success(t('clientsScopesSavedToast'), {
        description: t('clientsScopesSavedWithdrawn'),
      })
      void query.refresh()
      void detail.query.refresh()
    } finally {
      setPending(false)
    }
  }

  const loading = query.status === 'idle' || query.status === 'loading'

  return (
    <div className="space-y-4">
      <Alert status="default">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t('clientsScopesExplainTitle')}</Alert.Title>
          <Alert.Description>{t('clientsScopesExplainDescription')}</Alert.Description>
        </Alert.Content>
      </Alert>
      {client && !complete ? (
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>
              {t('clientsScopesTooMany', { count: PAGE_SIZE })}
            </Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={() => {
            void query.refresh()
            void detail.query.refresh()
          }}
          reloadPending={query.refreshing}
        />
      ) : null}
      <section className="space-y-4">
        <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-base font-semibold">{t('clientsScopesTitle')}</h2>
            <p className="mt-1 text-sm text-muted">{t('clientsScopesDescription')}</p>
          </div>
          {editable ? (
            <div className="flex flex-wrap gap-2">
              <PermissionPickerDialog
                subjectName={displayName}
                hint={t('clientsScopesPickerHint')}
                assignedIds={assignedIds}
                initialSelected={new Set()}
                initialMetadata={new Map()}
                permissionRead={rbac.permissionRead}
                resourcesRead={rbac.resourcesRead}
                disabled={pending}
                onApply={(_, metadata) => addScopes(metadata)}
              />
              <Button isDisabled={pending || !dirty} onPress={() => void save()}>
                {pending ? (
                  <Spinner size="sm" aria-label={t('working')} />
                ) : (
                  <Save className="size-4" aria-hidden="true" />
                )}
                {t('clientsScopesSave')}
              </Button>
            </div>
          ) : null}
        </header>
        <DataTable
          label={t('clientsScopesTitle')}
          loading={loading || query.refreshing}
          loadingLabel={t('tableLoading')}
          minWidth={760}
          columns={[
            { id: 'scope', label: t('clientsScopeColumn'), primary: true },
            { id: 'kind', label: t('clientsScopeKind'), primary: false },
            { id: 'granted', label: t('clientsScopeClientGranted'), primary: false },
            { id: 'actions', label: t('clientsColumnActions'), primary: false },
          ]}
        >
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState kind="empty" compact title={t('clientsScopesEmpty')} />
            )}
          >
            {rows.map((row) => {
              const api = Boolean(row.resourceId)
              return (
                <DataTable.Row key={row.id} id={row.id}>
                  <DataTable.Cell>
                    <div className="min-w-48">
                      <p className="font-medium">
                        {resolveLocalizedText(row.names, locale) ?? row.name}
                      </p>
                      <code className="text-xs text-muted">{row.code}</code>
                    </div>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    <Chip size="sm" variant="soft">
                      <Chip.Label>
                        {t(api ? 'clientsScopeKindApi' : 'clientsScopeKindProtocol')}
                      </Chip.Label>
                    </Chip>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    {api ? (
                      <Switch
                        size="sm"
                        aria-label={t('clientsScopeClientGrantedFor', { code: row.code })}
                        isSelected={row.clientGranted}
                        isDisabled={!editable || pending}
                        onChange={(clientGranted) => {
                          setFeedback(null)
                          setRows((current) =>
                            current.map((entry) =>
                              entry.id === row.id ? { ...entry, clientGranted } : entry,
                            ),
                          )
                        }}
                      >
                        <Switch.Control>
                          <Switch.Thumb />
                        </Switch.Control>
                      </Switch>
                    ) : (
                      <span className="text-xs text-muted">{t('clientsScopeProtocolOnly')}</span>
                    )}
                  </DataTable.Cell>
                  <DataTable.Cell>
                    {api && editable ? (
                      <TableRowActions
                        subject={row.code}
                        actions={[
                          {
                            id: 'remove',
                            label: t('clientsScopeRemove'),
                            danger: true,
                            onAction: () => {
                              setFeedback(null)
                              setRows((current) =>
                                current.filter((entry) => entry.id !== row.id),
                              )
                            },
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
        {dirty ? (
          <p className="text-xs text-muted">{t('clientsScopesUnsaved')}</p>
        ) : null}
      </section>
    </div>
  )
}
