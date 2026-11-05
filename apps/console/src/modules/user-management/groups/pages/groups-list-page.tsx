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
  ConsoleGroupsDocument,
  type ConsoleGroupsQuery,
  type ConsoleGroupsQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import {
  GroupKindChip,
  GroupStatusChip,
} from '#/modules/user-management/groups/components/group-status'
import {
  isGroupOrder,
  groupsFilterDraft,
  groupsQueryVariables,
  groupsSearchFromDraft,
  groupsSearchKey,
  hasGroupFilters,
  resolveLocalizedText,
  type GroupsFilterDraft,
  type GroupsSearch,
} from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

function GroupsTable({
  groups,
  ...controls
}: {
  groups: NonNullable<ConsoleGroupsQuery['groups']>['edges']
} & ResourceTableControls) {
  const navigate = useNavigate()
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const items = groups.map(({ node }) => {
    const name =
      resolveLocalizedText(node.names, locale) ?? node.name ?? node.id
    const description =
      resolveLocalizedText(node.descriptions, locale) ?? node.description
    return { id: node.id, node, name, description }
  })
  return (
    <ResourceTable
      id="groups"
      label={t('groupsTableLabel')}
      items={items}
      {...controls}
      columns={[
        {
          id: 'group',
          label: t('groupsColumnGroup'),
          primary: true,
          render: (row) => {
            const { node, name, description } = row
            return (
              <>
                <div className="min-w-56">
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
              </>
            )
          },
        },
        {
          id: 'kind',
          label: t('groupsColumnKind'),
          render: (row) => {
            const { node } = row
            return (
              <>
                <GroupKindChip builtIn={node.builtIn} />
              </>
            )
          },
        },
        {
          id: 'status',
          label: t('groupsColumnStatus'),
          render: (row) => {
            const { node } = row
            return (
              <>
                <GroupStatusChip enabled={node.enabled} />
              </>
            )
          },
        },
        {
          id: 'created',
          label: t('groupsColumnCreated'),
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
          label: t('groupsColumnUpdated'),
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
          label: t('groupsColumnActions'),
          render: (row) => {
            const { node, name } = row
            return (
              <>
                <TableRowActions
                  subject={name}
                  actions={[
                    {
                      id: 'view',
                      label: t('groupsViewAction'),
                      onAction: () => {
                        void navigate({
                          to: '/groups/$groupId',
                          params: { groupId: node.id },
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

export function GroupsListPage({ search }: { search: GroupsSearch }) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const searchKey = groupsSearchKey(search)
  const [draft, setDraft] = useState<GroupsFilterDraft>(() =>
    groupsFilterDraft(search),
  )
  const variables = useMemo<ConsoleGroupsQueryVariables | null>(
    () => (scope.groupsRead ? groupsQueryVariables(search) : null),
    [searchKey, scope.groupsRead],
  )
  const groups = useConsoleQuery<
    ConsoleGroupsQuery,
    ConsoleGroupsQueryVariables
  >(
    ConsoleGroupsDocument,
    variables,
    'ConsoleGroups',
    Boolean(variables),
    'missing_group_connection',
  )

  useEffect(() => {
    setDraft(groupsFilterDraft(search))
  }, [searchKey])

  const reset = () => {
    setDraft(groupsFilterDraft({}))
    void navigate({ to: '/groups', search: {} })
  }

  const apply = () => {
    void navigate({ to: '/groups', search: groupsSearchFromDraft(draft) })
  }

  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      void navigate({
        to: '/groups',
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
  })

  const header = (
    <PageHeader
      title={t('groupsTitle')}
      description={t('groupsDescription')}
      actions={
        scope.groupsWrite ? (
          <Button onPress={() => void navigate({ to: '/groups/new' })}>
            <Plus className="size-4" aria-hidden="true" />
            {t('groupsNewAction')}
          </Button>
        ) : undefined
      }
    />
  )

  function content() {
    if (!scope.groupsRead) {
      return (
        <RbacAccessRestricted
          title="groupsNoReadTitle"
          description="groupsNoReadDescription"

          onBack={() => void navigate({ to: '/' })}
          backLabel="goHome"
        />
      )
    }

    if (groups.stepUp && groups.status === 'error') {
      return (
        <StepUpPanel
          stepUp={groups.stepUp}
          hideDetails
          description={t('rbacStepUpDescription')}
          note={t('rbacStepUpNote')}
        />
      )
    }

    if (groups.status === 'error') {
      return (
        <AsyncState
          kind={groups.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(groups.failure, groups.forbidden))}
          description={t(
            failureDescriptionKey(groups.failure, groups.forbidden),
          )}
          requestId={groups.requestId}
          traceId={groups.traceId}
          issues={groups.errors}
          onRetry={() => void groups.refresh()}
        />
      )
    }

    if (groups.status !== 'ready' || !groups.data) {
      return (
        <div
          className="space-y-3 rounded-field border border-border bg-surface p-4"
          role="status"
          aria-live="polite"
          aria-label={t('groupsTableLoading')}
        >
          <span className="sr-only">{t('groupsTableLoading')}</span>
          <Skeleton className="h-10 w-full rounded-field" />
          {Array.from({ length: 5 }, (_, index) => (
            <Skeleton key={index} className="h-14 w-full rounded-field" />
          ))}
        </div>
      )
    }

    const connection = groups.data.groups
    const edges = connection.edges
    const emptyState = (() => {
      if (edges.length === 0) {
        if (hasGroupFilters(search) || search.after || search.before) {
          return (
            <AsyncState
              kind="empty"
              title={t('groupsNoResultsTitle')}
              description={t('groupsNoResultsDescription')}
              action={
                <Button variant="secondary" onPress={reset}>
                  {t('groupsClearFilters')}
                </Button>
              }
            />
          )
        }
        return (
          <AsyncState
            kind="empty"
            title={t('groupsEmptyTitle')}
            description={t('groupsEmptyDescription')}
            action={
              scope.groupsWrite ? (
                <Button onPress={() => void navigate({ to: '/groups/new' })}>
                  <Plus className="size-4" aria-hidden="true" />
                  {t('groupsNewAction')}
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
        {groups.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupsPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={groups.requestId}
                traceId={groups.traceId}
              />
              <ErrorDetails issues={groups.errors} />
            </Alert.Content>
          </Alert>
        ) : null}
        <GroupsTable
          emptyState={emptyState}
          groups={edges}
          order={search.order}
          onOrderChange={(order) => {
            if (order === undefined || isGroupOrder(order))
              void navigate({
                to: '/groups',
                search: {
                  ...search,
                  order,
                  after: undefined,
                  before: undefined,
                },
              })
          }}
          refreshing={groups.refreshing}
          onRefresh={() => void groups.refresh()}
          pagination={
            <CursorPagination
              label={t('groupsPaginationLabel')}
              pageCount={edges.length}
              totalCount={connection.totalCount}
              pageInfo={pageInfo}
              controller={pager}
              isDisabled={groups.refreshing}
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
            aria-label={t('groupsFiltersTitle')}
            onSubmit={(event) => {
              event.preventDefault()
              apply()
            }}
            className="collection-filter-controls flex flex-col gap-3 lg:flex-row lg:items-end"
          >
            <div className="min-w-0 flex-1">
              <UserTextField
                name="q"
                label={t('groupsFilterSearchLabel')}
                value={draft.q}
                onChange={(value) =>
                  setDraft((current) => ({ ...current, q: value }))
                }
                placeholder={t('groupsFilterSearchPlaceholder')}
                maxLength={256}
              />
            </div>
            <div className="sm:w-44">
              <UserSelectField
                name="enabled"
                label={t('groupsFilterEnabledLabel')}
                value={draft.enabled}
                onChange={(value) => {
                  if (
                    value === 'any' ||
                    value === 'enabled' ||
                    value === 'disabled'
                  ) {
                    setDraft((current) => ({ ...current, enabled: value }))
                  }
                }}
                options={[
                  { id: 'any', label: t('groupsFilterAny') },
                  { id: 'enabled', label: t('groupsFilterEnabledOnly') },
                  { id: 'disabled', label: t('groupsFilterDisabledOnly') },
                ]}
              />
            </div>

            <div className="flex flex-wrap gap-2">
              <Button type="submit">
                <Search className="size-4" aria-hidden="true" />
                {t('groupsApplyFilters')}
              </Button>
              <Button type="button" variant="secondary" onPress={reset}>
                <RotateCcw className="size-4" aria-hidden="true" />
                {t('groupsResetFilters')}
              </Button>
            </div>
          </form>
        </div>
        {content()}
      </ConsoleWorkspaceGate>
    </>
  )
}
