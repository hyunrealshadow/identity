import { TableRowActions } from '#/components/table-row-actions'
import { CursorPagination } from '#/components/cursor-pagination'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import {
  ResourceTable,
  type ResourceTableControls,
} from '#/components/resource-table'
import { Alert, Button, Skeleton } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { Plus, RotateCcw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { PageHeader } from '#/components/page-header'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleRolesDocument,
  type ConsoleRolesQuery,
  type ConsoleRolesQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  RoleBuiltInChip,
  RoleStatusChip,
} from '#/modules/user-management/roles/components/role-status'
import {
  roleDisplayDescription,
  roleDisplayName,
  roleIsBuiltIn,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import {
  isRoleOrder,
  rolesFilterDraft,
  rolesQueryVariables,
  rolesSearchFromDraft,
  rolesSearchKey,
  type RolesFilterDraft,
  type RolesSearch,
} from '#/modules/user-management/roles/lib/roles-search'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

function RolesTable({
  roles,
  ...controls
}: {
  roles: NonNullable<ConsoleRolesQuery['roles']>['edges']
} & ResourceTableControls) {
  const navigate = useNavigate()
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const items = roles.map(({ node }) => {
    const display = withRoleDisplayFields(node)
    const name = roleDisplayName(display, locale)
    const description = roleDisplayDescription(display, locale)
    return { id: node.id, node, display, name, description }
  })
  return (
    <ResourceTable
      id="roles"
      label={t('rolesTableLabel')}
      items={items}
      {...controls}
      columns={[
        {
          id: 'role',
          label: t('rolesColumnRole'),
          primary: true,
          sort: 'NAME',
          render: (row) => {
            const { node, display, name, description } = row
            return (
              <>
                <div className="min-w-56">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      to="/roles/$roleId"
                      params={{ roleId: node.id }}
                      className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
                    >
                      {name}
                    </Link>
                    <RoleBuiltInChip builtIn={roleIsBuiltIn(display)} />
                  </div>
                  {description ? (
                    <p className="mt-1 line-clamp-2 max-w-80 text-xs leading-4 text-muted">
                      {description}
                    </p>
                  ) : null}
                </div>
              </>
            )
          },
        },
        {
          id: 'status',
          label: t('rolesColumnStatus'),
          render: (row) => {
            const { node } = row
            return (
              <>
                <RoleStatusChip enabled={node.enabled} />
              </>
            )
          },
        },
        {
          id: 'created',
          label: t('rolesColumnCreated'),
          sort: 'CREATED_AT',
          render: (row) => {
            const { node } = row
            return (
              <>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(node.createdAt, locale, timeZone)}
                </span>
              </>
            )
          },
        },
        {
          id: 'updated',
          label: t('rolesColumnUpdated'),
          render: (row) => {
            const { node } = row
            return (
              <>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(node.updatedAt, locale, timeZone)}
                </span>
              </>
            )
          },
        },
        {
          id: 'actions',
          label: t('rolesColumnActions'),
          render: (row) => {
            const { node, name } = row
            return (
              <>
                <TableRowActions
                  subject={name}
                  actions={[
                    {
                      id: 'view',
                      label: t('rolesViewAction'),
                      onAction: () => {
                        void navigate({
                          to: '/roles/$roleId',
                          params: { roleId: node.id },
                        })
                      },
                    },
                  ]}
                />
              </>
            )
          },
        },
      ]}
    />
  )
}

export function RolesListPage({ search }: { search: RolesSearch }) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const searchKey = rolesSearchKey(search)
  const [draft, setDraft] = useState<RolesFilterDraft>(() =>
    rolesFilterDraft(search),
  )
  const variables = useMemo<ConsoleRolesQueryVariables | null>(
    () =>
      scope.rolesRead
        ? (rolesQueryVariables(search) as ConsoleRolesQueryVariables)
        : null,
    [searchKey, scope.rolesRead],
  )
  const roles = useConsoleQuery<ConsoleRolesQuery, ConsoleRolesQueryVariables>(
    ConsoleRolesDocument,
    variables,
    Boolean(variables),
    'missing_role_connection',
    { keepPreviousData: true },
  )

  useEffect(() => {
    setDraft(rolesFilterDraft(search))
  }, [searchKey])

  const reset = () => {
    setDraft(rolesFilterDraft({}))
    void navigate({ to: '/roles', search: {} })
  }

  const apply = () => {
    void navigate({ to: '/roles', search: rolesSearchFromDraft(draft) })
  }

  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      void navigate({
        to: '/roles',
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
  })

  const header = (
    <PageHeader
      title={t('rolesTitle')}
      description={t('rolesDescription')}
      actions={
        scope.rolesWrite ? (
          <Button onPress={() => void navigate({ to: '/roles/new' })}>
            <Plus className="size-4" aria-hidden="true" />
            {t('rolesNewAction')}
          </Button>
        ) : undefined
      }
    />
  )

  function content() {
    if (!scope.rolesRead) {
      return (
        <RbacAccessRestricted
          title="rolesNoReadTitle"
          description="rolesNoReadDescription"

          onBack={() => void navigate({ to: '/' })}
          backLabel="goHome"
        />
      )
    }

    if (roles.stepUp && roles.status === 'error') {
      return (
        <StepUpPanel
          stepUp={roles.stepUp}
          hideDetails
          description={t('rbacStepUpDescription')}
          note={t('rbacStepUpNote')}
        />
      )
    }

    if (roles.status === 'error') {
      return (
        <AsyncState
          kind={roles.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(roles.failure, roles.forbidden))}
          description={t(failureDescriptionKey(roles.failure, roles.forbidden))}
          requestId={roles.requestId}
          traceId={roles.traceId}
          issues={roles.errors}
          onRetry={() => void roles.refresh()}
        />
      )
    }

    if (roles.status !== 'ready' || !roles.data) {
      return (
        <div
          className="space-y-3 rounded-field border border-border bg-surface p-4"
          role="status"
          aria-live="polite"
          aria-label={t('rolesTableLoading')}
        >
          <span className="sr-only">{t('rolesTableLoading')}</span>
          <Skeleton className="h-10 w-full rounded-field" />
          {Array.from({ length: 5 }, (_, index) => (
            <Skeleton key={index} className="h-14 w-full rounded-field" />
          ))}
        </div>
      )
    }

    const connection = roles.data.roles
    const edges = connection.edges
    const emptyState = (() => {
      if (edges.length === 0) {
        if (search.q || search.status || search.after || search.before) {
          return (
            <AsyncState
              kind="empty"
              title={t('rolesNoResultsTitle')}
              description={t('rolesNoResultsDescription')}
              action={
                <Button variant="secondary" onPress={reset}>
                  {t('rolesClearFilters')}
                </Button>
              }
            />
          )
        }
        return (
          <AsyncState
            kind="empty"
            title={t('rolesEmptyTitle')}
            description={t('rolesEmptyDescription')}
            action={
              scope.rolesWrite ? (
                <Button onPress={() => void navigate({ to: '/roles/new' })}>
                  <Plus className="size-4" aria-hidden="true" />
                  {t('rolesNewAction')}
                </Button>
              ) : undefined
            }
          />
        )
      }
      return undefined
    })()

    const { pageInfo } = connection
    return (
      <div className="space-y-4">
        {roles.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('rolesPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={roles.requestId}
                traceId={roles.traceId}
              />
              <ErrorDetails issues={roles.errors} />
            </Alert.Content>
          </Alert>
        ) : null}
        <RolesTable
          emptyState={emptyState}
          roles={edges}
          order={search.order}
          onOrderChange={(order) => {
            if (order === undefined || isRoleOrder(order))
              void navigate({
                to: '/roles',
                search: {
                  ...search,
                  order,
                  after: undefined,
                  before: undefined,
                },
              })
          }}
          refreshing={roles.refreshing}
          onRefresh={() => void roles.refresh()}
          pagination={
            <CursorPagination
              label={t('rolesPaginationLabel')}
              pageCount={edges.length}
              totalCount={connection.totalCount}
              pageInfo={pageInfo}
              controller={pager}
              isDisabled={roles.refreshing}
            />
          }
        />
      </div>
    )
  }

  return (
    <>
      {header}
      <ConsoleWorkspaceGate>
        <div className="collection-filters">
          <form
            aria-label={t('rolesFiltersTitle')}
            onSubmit={(event) => {
              event.preventDefault()
              apply()
            }}
            className="collection-filter-controls flex flex-col gap-3 lg:flex-row lg:items-end"
          >
            <div className="min-w-0 flex-1">
              <UserTextField
                name="q"
                label={t('rolesFilterSearchLabel')}
                value={draft.q}
                onChange={(value) =>
                  setDraft((current) => ({ ...current, q: value }))
                }
                placeholder={t('rolesFilterSearchPlaceholder')}
                maxLength={256}
              />
            </div>
            <div className="sm:w-52">
              <UserSelectField
                name="status"
                label={t('rolesFilterStatusLabel')}
                value={draft.status}
                onChange={(value) => {
                  if (
                    value === 'any' ||
                    value === 'enabled' ||
                    value === 'disabled'
                  ) {
                    setDraft((current) => ({ ...current, status: value }))
                  }
                }}
                options={[
                  { id: 'any', label: t('rolesFilterAny') },
                  { id: 'enabled', label: t('rolesFilterEnabled') },
                  { id: 'disabled', label: t('rolesFilterDisabled') },
                ]}
              />
            </div>

            <div className="flex flex-wrap gap-2">
              <Button type="submit">
                <Search className="size-4" aria-hidden="true" />
                {t('rolesApplyFilters')}
              </Button>
              <Button type="button" variant="secondary" onPress={reset}>
                <RotateCcw className="size-4" aria-hidden="true" />
                {t('rolesResetFilters')}
              </Button>
            </div>
          </form>
        </div>
        {content()}
      </ConsoleWorkspaceGate>
    </>
  )
}
