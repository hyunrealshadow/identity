import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Spinner } from '@identity/ui/components/spinner'
import { Switch } from '@identity/ui/components/switch'
import { DataTable } from '@identity/ui/data-table'
import { Info, Save, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleClientScopesDocument,
  ConsoleProtocolScopesDocument,
  type ConsoleClientScopesQuery,
  type ConsoleClientScopesQueryVariables,
  type ConsoleProtocolScopesQuery,
  type ConsoleProtocolScopesQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { PermissionPickerDialog } from '#/modules/user-management/roles/components/permission-picker-dialog'
import type { StagedPermission } from '#/modules/user-management/roles/lib/permission-selection'
import { useClientDetail } from '../components/client-detail-shell'
import { useClientMutations } from '../hooks/client-mutations'

/** One page covers every realistic client; larger sets are read-only here. */
const PAGE_SIZE = 100

/** Display order for login scopes; codes not listed follow alphabetically. */
const PROTOCOL_SCOPE_ORDER: readonly string[] = [
  'openid',
  'profile',
  'email',
  'address',
  'phone',
  'offline_access',
]

function protocolScopeRank(code: string) {
  const index = PROTOCOL_SCOPE_ORDER.indexOf(code)
  return index === -1 ? PROTOCOL_SCOPE_ORDER.length : index
}

interface ScopeRow {
  id: string
  code: string
  name: string
  names: ReadonlyArray<{ locale: string; value: string }>
  /** `null` marks a protocol scope such as `openid`. */
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

/** Field paths `scopes.<code>` name the scope a save rejected. */
function rejectedScopeCodes(feedback: RbacFeedbackState | null): Set<string> {
  const prefix = 'scopes.'
  return new Set(
    (feedback?.errors ?? [])
      .flatMap((issue) => issue.fields)
      .filter((field) => field.path.startsWith(prefix))
      .map((field) => field.path.slice(prefix.length)),
  )
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
    true,
    'missing_client_scopes',
    { keepPreviousData: sameVariable('id') },
  )
  const protocolVariables = useMemo<ConsoleProtocolScopesQueryVariables>(
    () => ({ first: PAGE_SIZE }),
    [],
  )
  const protocolCatalog = useConsoleQuery<
    ConsoleProtocolScopesQuery,
    ConsoleProtocolScopesQueryVariables
  >(
    ConsoleProtocolScopesDocument,
    rbac.scopesRead ? protocolVariables : null,
    rbac.scopesRead,
    'missing_protocol_scopes',
  )
  const server = useMemo(() => rowsFrom(query.data), [query.data])
  // Local edits live apart from the server rows so a refetch (for example
  // after reauthentication) cannot discard them; `null` means "unchanged".
  const [draft, setDraft] = useState<ScopeRow[] | null>(null)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const rows = draft ?? server
  const setRows = (update: (current: ScopeRow[]) => ScopeRow[]) =>
    setDraft((current) => update(current ?? server))

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
    JSON.stringify(list.map((row) => [row.id, row.clientGranted]).sort())
  const dirty = signature(rows) !== signature(server)
  const assignedIds = new Set(rows.map((row) => row.id))
  const apiRows = rows.filter((row) => row.resourceId)
  const protocolRows = rows.filter((row) => !row.resourceId)
  const rejected = rejectedScopeCodes(feedback)
  // The catalog lists every selectable protocol scope; assigned ones the
  // catalog cannot show (no catalog read, or a disabled definition) stay
  // visible so the list never hides an existing assignment.
  const protocolOptions: Array<{
    id: string
    code: string
    name: string
    names: ReadonlyArray<{ locale: string; value: string }>
    description: string
  }> = [
    ...(protocolCatalog.data?.scopes.edges ?? []).map((edge) => ({
      id: edge.node.id,
      code: edge.node.code,
      name: edge.node.name,
      names: edge.node.names,
      description:
        resolveLocalizedText(edge.node.descriptions, locale) ?? edge.node.description,
    })),
  ]
  for (const row of protocolRows) {
    if (!protocolOptions.some((option) => option.id === row.id)) {
      protocolOptions.push({
        id: row.id,
        code: row.code,
        name: row.name,
        names: row.names,
        description: '',
      })
    }
  }
  protocolOptions.sort(
    (a, b) =>
      protocolScopeRank(a.code) - protocolScopeRank(b.code) ||
      a.code.localeCompare(b.code),
  )

  function setProtocolScopes(ids: string[]) {
    setFeedback(null)
    setRows((current) => [
      ...current.filter((row) => row.resourceId || ids.includes(row.id)),
      ...protocolOptions
        .filter(
          (option) =>
            ids.includes(option.id) && !current.some((row) => row.id === option.id),
        )
        .map((option) => ({
          id: option.id,
          code: option.code,
          name: option.name,
          names: option.names,
          resourceId: null,
          clientGranted: false,
        })),
    ])
  }
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
        scopes: rows.map((row) => ({
          scopeId: row.id,
          clientGranted: row.resourceId ? row.clientGranted : false,
        })),
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
      setDraft(null)
      toast.success(t('clientsScopesSavedToast'), {
        description: t('clientsScopesSavedWithdrawn'),
      })
    } finally {
      setPending(false)
    }
  }

  const loading = query.status === 'idle' || query.status === 'loading'

  return (
    <div className="space-y-4">
      <Alert className="console-card border border-border">
        <Info aria-hidden="true" />
        <AlertTitle>{t('clientsScopesExplainTitle')}</AlertTitle>
        <AlertDescription>{t('clientsScopesExplainDescription')}</AlertDescription>
      </Alert>
      {client && !complete ? (
        <Alert className="console-card border border-border text-warning">
          <TriangleAlert aria-hidden="true" />
          <AlertDescription>
            {t('clientsScopesTooMany', { count: PAGE_SIZE })}
          </AlertDescription>
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
      <SettingsGroup
        title={t('clientsProtocolScopesTitle')}
        description={t('clientsProtocolScopesDescription')}
        density="compact"
      >
        {loading || (rbac.scopesRead && protocolCatalog.status !== 'ready' && protocolCatalog.status !== 'error') ? (
          <SettingsRow description={t('tableLoading')} />
        ) : protocolOptions.length === 0 ? (
          <SettingsRow description={t('clientsProtocolScopesEmpty')} />
        ) : (
          protocolOptions.map((option) => {
            const name = resolveLocalizedText(option.names, locale) ?? option.name
            const selected = protocolRows.map((row) => row.id)
            return (
              <SettingsRow
                key={option.id}
                label={
                  <>
                    {name} <code className="ml-1 text-xs text-muted-foreground">{option.code}</code>
                  </>
                }
                description={
                  rejected.has(option.code) ? (
                    <span className="text-destructive">{option.description ?? option.code}</span>
                  ) : (
                    option.description
                  )
                }
                action={
                  <Switch
                    aria-label={name}
                    checked={selected.includes(option.id)}
                    disabled={!editable || pending}
                    onCheckedChange={(on) =>
                      setProtocolScopes(
                        on
                          ? [...selected, option.id]
                          : selected.filter((id) => id !== option.id),
                      )
                    }
                  />
                }
              />
            )
          })
        )}
      </SettingsGroup>
      <section>
        <header className="mb-2 flex flex-col gap-3 px-1 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-sm font-semibold">{t('clientsScopesTitle')}</h2>
            <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{t('clientsScopesDescription')}</p>
          </div>
          {editable ? (
            <PermissionPickerDialog
              subjectName={displayName}
              hint={t('clientsScopesPickerHint')}
              assignedIds={assignedIds}
              initialSelected={new Set()}
              initialMetadata={new Map()}
              permissionRead={rbac.permissionRead}
              resourcesRead={rbac.resourcesRead}
              disabled={pending}
              triggerSize="md"
              onApply={(_, metadata) => addScopes(metadata)}
            />
          ) : null}
        </header>
        <DataTable
          label={t('clientsScopesTitle')}
          loading={loading || query.refreshing}
          loadingLabel={t('tableLoading')}
          minWidth={640}
          density="compact"
          maxHeight="clamp(12rem, calc(100dvh - 26rem), 32rem)"
          columns={[
            { id: 'scope', label: t('clientsScopeColumn'), primary: true },
            { id: 'granted', label: t('clientsScopeClientGranted'), primary: false },
            { id: 'actions', label: t('clientsColumnActions'), primary: false },
          ]}
        >
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState kind="empty" compact title={t('clientsScopesEmpty')} />
            )}
          >
            {apiRows.map((row) => {
              const invalid = rejected.has(row.code)
              return (
                <DataTable.Row key={row.id} id={row.id}>
                  <DataTable.Cell>
                    <div className="min-w-48">
                      <p className="font-medium">
                        {resolveLocalizedText(row.names, locale) ?? row.name}
                      </p>
                      <code className="text-xs text-muted-foreground">{row.code}</code>
                    </div>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    <div className="flex flex-col gap-1">
                      <Switch
                        aria-label={t('clientsScopeClientGrantedFor', { code: row.code })}
                        checked={row.clientGranted}
                        aria-invalid={invalid || undefined}
                        disabled={!editable || pending}
                        onCheckedChange={(clientGranted) => {
                          setFeedback(null)
                          setRows((current) =>
                            current.map((entry) =>
                              entry.id === row.id ? { ...entry, clientGranted } : entry,
                            ),
                          )
                        }}
                      />
                      {invalid ? (
                        <span className="text-xs text-destructive">
                          {t('clientsScopeClientGrantRejected')}
                        </span>
                      ) : null}
                    </div>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    {editable ? (
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
      </section>
      {editable ? (
        <div className="flex flex-wrap items-center justify-end gap-3">
          {dirty ? (
            <span className="text-xs text-muted-foreground">{t('clientsScopesUnsaved')}</span>
          ) : null}
          <Button disabled={pending || !dirty} onClick={() => void save()}>
            {pending ? (
              <Spinner aria-label={t('working')} />
            ) : (
              <Save className="size-4" aria-hidden="true" />
            )}
            {t('clientsScopesSave')}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
