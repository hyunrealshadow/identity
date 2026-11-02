import { TableRowActions } from '#/components/table-row-actions'
import { DataTable } from '@identity/ui/data-table'
import { Alert, Button, Pagination } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { RotateCcw, Search } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { useIntl } from 'react-intl'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleRoleGroupsDocument,
  type ConsoleRoleGroupsQuery,
  type ConsoleRoleGroupsQueryVariables,
} from '#/gql/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import {
  useLocale,
  useTranslator,
  type Locale,
  type MessageValues,
} from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import {
  GroupKindChip,
  GroupStatusChip,
} from '#/modules/user-management/groups/components/group-status'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import enUS from '#/modules/user-management/roles/locales/en-US'
import zhCN from '#/modules/user-management/roles/locales/zh-CN'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 5

type RoleGroupsMessageKey = keyof typeof enUS
type RoleGroupsFilterState = {
  query: string
  kind: 'any' | 'builtin' | 'custom'
  order: 'CREATED_AT_ASC' | 'CREATED_AT_DESC'
}
type RoleGroupsConnection = NonNullable<
  ConsoleRoleGroupsQuery['role']
>['groups']

const DEFAULT_ROLE_GROUPS_FILTER: RoleGroupsFilterState = {
  query: '',
  kind: 'any',
  order: 'CREATED_AT_DESC',
}

const roleGroupsMessages: Record<
  Locale,
  Record<RoleGroupsMessageKey, string>
> = {
  'en-US': enUS,
  'zh-CN': zhCN,
}

/**
 * The console shell owns locale selection and persistence. This view keeps its
 * own typed catalog so it can be reviewed before the parent merges the module
 * keys into the shared message registry.
 */
function useRoleGroupsTranslator() {
  const intl = useIntl()
  const { locale } = useLocale()
  return useCallback(
    (key: RoleGroupsMessageKey, values: MessageValues = {}) =>
      intl.formatMessage(
        { id: key, defaultMessage: roleGroupsMessages[locale][key] },
        values,
      ),
    [intl, locale],
  )
}

function roleGroupsHasFilters(state: RoleGroupsFilterState): boolean {
  return Boolean(state.query.trim()) || state.kind !== 'any'
}

function roleGroupsQueryFilter(
  state: RoleGroupsFilterState,
): NonNullable<ConsoleRoleGroupsQueryVariables['filter']> {
  const filter: NonNullable<ConsoleRoleGroupsQueryVariables['filter']> = {
    enabled: true,
  }
  const query = state.query.trim()
  if (query) filter.query = query
  if (state.kind === 'builtin') filter.builtIn = true
  if (state.kind === 'custom') filter.builtIn = false
  return filter
}

export function RoleGroupsPage({ roleId }: { roleId: string }) {
  const t = useTranslator()
  const tr = useRoleGroupsTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const canRead = scope.rolesRead && scope.groupsRead && scope.groupRolesRead
  const [draft, setDraft] = useState<RoleGroupsFilterState>(
    DEFAULT_ROLE_GROUPS_FILTER,
  )
  const [applied, setApplied] = useState<RoleGroupsFilterState>(
    DEFAULT_ROLE_GROUPS_FILTER,
  )
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()

  const variables = useMemo<ConsoleRoleGroupsQueryVariables | null>(
    () =>
      canRead
        ? {
            roleId,
            filter: roleGroupsQueryFilter(applied),
            orderBy: applied.order,
            ...cursorPage(PAGE_SIZE, after, before),
          }
        : null,
    [after, applied, before, canRead, roleId],
  )
  const groups = useConsoleQuery<
    ConsoleRoleGroupsQuery,
    ConsoleRoleGroupsQueryVariables
  >(
    ConsoleRoleGroupsDocument,
    variables,
    'ConsoleRoleGroups',
    Boolean(variables),
    'missing_role_groups',
  )

  function applyFilters() {
    setApplied({
      query: draft.query,
      kind: draft.kind,
      order: draft.order,
    })
    setAfter(undefined)
    setBefore(undefined)
  }

  function resetFilters() {
    setDraft(DEFAULT_ROLE_GROUPS_FILTER)
    setApplied(DEFAULT_ROLE_GROUPS_FILTER)
    setAfter(undefined)
    setBefore(undefined)
  }

  function goNext(cursor: string | null) {
    if (!cursor) return
    setAfter(cursor)
    setBefore(undefined)
  }

  function goPrevious(cursor: string | null) {
    if (!cursor) return
    setBefore(cursor)
    setAfter(undefined)
  }

  if (!canRead) {
    const missingRolesRead = !scope.rolesRead
    const missingGroupsRead = !scope.groupsRead
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            missingRolesRead
              ? 'rolesNoReadTitle'
              : missingGroupsRead
                ? 'groupsNoReadTitle'
                : 'groupRolesNoReadTitle'
          }
          description={
            missingRolesRead
              ? 'rolesNoReadDescription'
              : missingGroupsRead
                ? 'groupsNoReadDescription'
                : 'groupRolesNoReadDescription'
          }

          onBack={() => void navigate({ to: '/roles' })}
          backLabel="backToRoles"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (groups.status === 'error') {
    if (groups.stepUp) {
      return (
        <ConsoleWorkspaceGate>
          <StepUpPanel
            stepUp={groups.stepUp}
            hideDetails
            description={tr('roleGroupsStepUpDescription')}
            note={tr('roleGroupsStepUpNote')}
          />
        </ConsoleWorkspaceGate>
      )
    }
    return (
      <ConsoleWorkspaceGate>
        <AsyncState
          kind={
            groups.forbidden
              ? 'forbidden'
              : groups.unauthorized
                ? 'unauthorized'
                : 'error'
          }
          title={t(failureTitleKey(groups.failure, groups.forbidden))}
          description={t(
            failureDescriptionKey(groups.failure, groups.forbidden),
          )}
          requestId={groups.requestId}
          traceId={groups.traceId}
          issues={groups.errors}
          onRetry={() => void groups.refresh()}
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (groups.status !== 'ready' || !groups.data) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={tr('roleGroupsLoading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const role = groups.data.role
  if (!role) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState
          kind="notFound"
          title={tr('roleGroupsNotFoundTitle')}
          description={tr('roleGroupsNotFoundDescription')}
        />
      </ConsoleWorkspaceGate>
    )
  }

  const connection = role.groups
  const edges = connection.edges
  const filtered = roleGroupsHasFilters(applied)

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {groups.stepUp ? (
          <StepUpPanel
            stepUp={groups.stepUp}
            hideDetails
            description={tr('roleGroupsStepUpDescription')}
            note={tr('roleGroupsStepUpNote')}
          />
        ) : null}

        <section className="space-y-4">
          <header className="py-2">
            <h2 className="text-base font-semibold">
              {tr('roleGroupsListTitle')}
            </h2>
            <p className="mt-1 text-sm text-muted">
              {tr('roleGroupsListDescription')}
            </p>
          </header>
          <div className="p-0">
            <form
              aria-label={tr('roleGroupsFiltersLabel')}
              onSubmit={(event) => {
                event.preventDefault()
                applyFilters()
              }}
              className="collection-filter-controls flex flex-col gap-3 py-2 lg:flex-row lg:items-end"
            >
              <div className="min-w-0 flex-1">
                <UserTextField
                  name="role-groups-query"
                  label={tr('roleGroupsSearchLabel')}
                  value={draft.query}
                  onChange={(value) =>
                    setDraft((current) => ({ ...current, query: value }))
                  }
                  placeholder={tr('roleGroupsSearchPlaceholder')}
                  maxLength={255}
                />
              </div>
              <div className="sm:w-44">
                <UserSelectField
                  name="role-groups-kind"
                  label={tr('roleGroupsKindLabel')}
                  value={draft.kind}
                  onChange={(value) => {
                    if (
                      value === 'any' ||
                      value === 'builtin' ||
                      value === 'custom'
                    ) {
                      setDraft((current) => ({ ...current, kind: value }))
                    }
                  }}
                  options={[
                    { id: 'any', label: tr('roleGroupsKindAny') },
                    { id: 'builtin', label: tr('roleGroupsKindBuiltIn') },
                    { id: 'custom', label: tr('roleGroupsKindCustom') },
                  ]}
                />
              </div>
              <div className="sm:w-48">
                <UserSelectField
                  name="role-groups-order"
                  label={tr('roleGroupsOrderLabel')}
                  value={draft.order}
                  onChange={(value) => {
                    if (
                      value === 'CREATED_AT_ASC' ||
                      value === 'CREATED_AT_DESC'
                    ) {
                      setDraft((current) => ({ ...current, order: value }))
                    }
                  }}
                  options={[
                    {
                      id: 'CREATED_AT_DESC',
                      label: tr('roleGroupsOrderCreatedDesc'),
                    },
                    {
                      id: 'CREATED_AT_ASC',
                      label: tr('roleGroupsOrderCreatedAsc'),
                    },
                  ]}
                />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button type="submit">
                  <Search className="size-4" aria-hidden="true" />
                  {tr('roleGroupsApplyFilters')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onPress={resetFilters}
                >
                  <RotateCcw className="size-4" aria-hidden="true" />
                  {tr('roleGroupsResetFilters')}
                </Button>
              </div>
            </form>

            {groups.partial ? (
              <div className="p-3">
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>{tr('roleGroupsPartialTitle')}</Alert.Title>
                    <Alert.Description>
                      {tr('roleGroupsPartialDescription')}
                    </Alert.Description>
                    <RequestCorrelation
                      requestId={groups.requestId}
                      traceId={groups.traceId}
                    />
                    <ErrorDetails issues={groups.errors} />
                  </Alert.Content>
                </Alert>
              </div>
            ) : null}

            {edges.length === 0 ? (
              <div className="p-4">
                {filtered ? (
                  <AsyncState
                    kind="empty"
                    compact
                    title={tr('roleGroupsNoResultsTitle')}
                    description={tr('roleGroupsNoResultsDescription')}
                    action={
                      <Button variant="secondary" onPress={resetFilters}>
                        {tr('roleGroupsClearFilters')}
                      </Button>
                    }
                  />
                ) : (
                  <AsyncState
                    kind="empty"
                    compact
                    title={tr('roleGroupsEmptyTitle')}
                    description={tr('roleGroupsEmptyDescription')}
                  />
                )}
              </div>
            ) : (
              <RoleGroupsTable edges={edges} />
            )}
          </div>
          {edges.length > 0 ? (
            <footer className="border-t border-separator pt-4">
              <RoleGroupsPagination
                connection={connection}
                onNext={goNext}
                onPrevious={goPrevious}
              />
            </footer>
          ) : null}
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )
}

function RoleGroupsTable({ edges }: { edges: RoleGroupsConnection['edges'] }) {
  const navigate = useNavigate()
  const tr = useRoleGroupsTranslator()
  const { locale, timeZone } = useLocale()
  return (
    <DataTable
      label={tr('roleGroupsTableLabel')}
      minWidth={760}
      columns={[
        {
          id: 'roleGroupsColumnGroup',
          label: tr('roleGroupsColumnGroup'),
          primary: true,
        },
        {
          id: 'roleGroupsColumnKind',
          label: tr('roleGroupsColumnKind'),
          primary: false,
        },
        {
          id: 'roleGroupsColumnStatus',
          label: tr('roleGroupsColumnStatus'),
          primary: false,
        },
        {
          id: 'roleGroupsColumnUpdated',
          label: tr('roleGroupsColumnUpdated'),
          primary: false,
        },
        {
          id: 'roleGroupsColumnActions',
          label: tr('roleGroupsColumnActions'),
          primary: false,
        },
      ]}
    >
      <DataTable.Body>
        {edges.map(({ node }) => {
          const name =
            resolveLocalizedText(node.names, locale) ?? node.name ?? node.id
          const description =
            resolveLocalizedText(node.descriptions, locale) ?? node.description
          return (
            <DataTable.Row key={node.id} id={node.id}>
              <DataTable.Cell>
                <div className="min-w-52">
                  <Link
                    to="/groups/$groupId"
                    params={{ groupId: node.id }}
                    className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
                  >
                    {name}
                  </Link>
                  {description ? (
                    <p className="mt-1 max-w-md text-xs leading-5 text-muted">
                      {description}
                    </p>
                  ) : null}
                </div>
              </DataTable.Cell>
              <DataTable.Cell>
                <GroupKindChip builtIn={node.builtIn} />
              </DataTable.Cell>
              <DataTable.Cell>
                <GroupStatusChip enabled={node.enabled} />
              </DataTable.Cell>
              <DataTable.Cell>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(node.updatedAt, locale, timeZone)}
                </span>
              </DataTable.Cell>
              <DataTable.Cell>
                <TableRowActions
                  subject={name}
                  actions={[
                    {
                      id: 'view',
                      label: tr('roleGroupsViewAction'),
                      onAction: () => {
                        void navigate({
                          to: '/groups/$groupId',
                          params: { groupId: node.id },
                        })
                      },
                    },
                  ]}
                />
              </DataTable.Cell>
            </DataTable.Row>
          )
        })}
      </DataTable.Body>
    </DataTable>
  )
}

function RoleGroupsPagination({
  connection,
  onNext,
  onPrevious,
}: {
  connection: RoleGroupsConnection
  onNext: (cursor: string | null) => void
  onPrevious: (cursor: string | null) => void
}) {
  const tr = useRoleGroupsTranslator()
  const { pageInfo } = connection
  return (
    <Pagination aria-label={tr('roleGroupsPaginationLabel')}>
      <Pagination.Summary>
        {tr('roleGroupsPageSummary', { count: connection.edges.length })}
      </Pagination.Summary>
      <Pagination.Content>
        <Pagination.Item>
          <Pagination.Previous
            isDisabled={!pageInfo.hasPreviousPage || !pageInfo.startCursor}
            onPress={() => onPrevious(pageInfo.startCursor)}
          >
            <Pagination.PreviousIcon />
            {tr('roleGroupsPreviousPage')}
          </Pagination.Previous>
        </Pagination.Item>
        <Pagination.Item>
          <Pagination.Next
            isDisabled={!pageInfo.hasNextPage || !pageInfo.endCursor}
            onPress={() => onNext(pageInfo.endCursor)}
          >
            {tr('roleGroupsNextPage')}
            <Pagination.NextIcon />
          </Pagination.Next>
        </Pagination.Item>
      </Pagination.Content>
    </Pagination>
  )
}
