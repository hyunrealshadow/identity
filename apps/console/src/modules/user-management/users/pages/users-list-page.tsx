import { TableRowActions } from '#/components/table-row-actions'
import { CursorPagination } from '#/components/cursor-pagination'
import { DatePickerField } from '#/components/date-picker-field'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import {
  ResourceTable,
  type ResourceTableControls,
} from '#/components/resource-table'
import { Alert, Button, Disclosure, Skeleton } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { Plus, RotateCcw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { PageHeader } from '#/components/page-header'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import { UserReadRestricted } from '#/modules/user-management/users/components/user-access'
import { UserStatusBadges } from '#/modules/user-management/users/components/user-status'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  useUsers,
  type UserSummary,
} from '#/modules/user-management/users/hooks/use-users'
import { userManagementScope } from '#/modules/user-management/users/lib/user-scope'
import {
  emptyUsersFilterDraft,
  hasUserFilters,
  isUserOrder,
  usersFilterDraft,
  usersQueryVariables,
  usersSearchFromDraft,
  usersSearchIssues,
  usersSearchKey,
  type UsersFilterDraft,
  type UsersSearch,
  type UsersSearchIssue,
} from '#/modules/user-management/users/lib/users-search'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

function UsersTable({
  users,
  canEdit,
  ...controls
}: {
  users: ReadonlyArray<UserSummary>
  canEdit: boolean
} & ResourceTableControls) {
  const navigate = useNavigate()
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const items = users
  return (
    <ResourceTable
      id="users"
      label={t('usersTableLabel')}
      items={items}
      {...controls}
      columns={[
        {
          id: 'user',
          label: t('usersColumnUser'),
          primary: true,
          sort: 'USERNAME',
          render: (user) => {
            return (
              <>
                <div className="w-56 max-w-full sm:w-64">
                  <Link
                    to="/users/$userId"
                    params={{ userId: user.id }}
                    title={user.username}
                    className="block truncate font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
                  >
                    {user.username}
                  </Link>
                  <p
                    className="mt-0.5 truncate text-xs text-muted"
                    title={user.email}
                  >
                    {user.email}
                  </p>
                </div>
              </>
            )
          },
        },
        {
          id: 'status',
          label: t('usersColumnStatus'),
          render: (user) => {
            return (
              <>
                <UserStatusBadges user={user} />
              </>
            )
          },
        },
        {
          id: 'created',
          label: t('usersColumnCreated'),
          sort: 'CREATED_AT',
          render: (user) => {
            return (
              <>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(user.createdAt, locale, timeZone)}
                </span>
              </>
            )
          },
        },
        {
          id: 'updated',
          label: t('usersColumnUpdated'),
          render: (user) => {
            return (
              <>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(user.updatedAt, locale, timeZone)}
                </span>
              </>
            )
          },
        },
        {
          id: 'actions',
          label: t('usersColumnActions'),
          render: (user) => {
            return (
              <>
                <TableRowActions
                  subject={user.username}
                  actions={[
                    {
                      id: 'view',
                      label: t('usersViewDetails'),
                      onAction: () => {
                        void navigate({
                          to: '/users/$userId',
                          params: { userId: user.id },
                        })
                      },
                    },
                    ...(canEdit
                      ? [
                          {
                            id: 'edit',
                            label: t('usersEditAction'),
                            onAction: () => {
                              void navigate({
                                to: '/users/$userId/edit',
                                params: { userId: user.id },
                              })
                            },
                          },
                        ]
                      : []),
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

function UsersTableLoading() {
  const t = useTranslator()

  return (
    <div
      className="space-y-3 rounded-field border border-border bg-surface p-4"
      role="status"
      aria-live="polite"
      aria-label={t('usersTableLoading')}
    >
      <span className="sr-only">{t('usersTableLoading')}</span>
      <Skeleton className="h-10 w-full rounded-field" />
      {Array.from({ length: 5 }, (_, index) => (
        <Skeleton key={index} className="h-14 w-full rounded-field" />
      ))}
    </div>
  )
}

function issueMessage(
  issue: UsersSearchIssue,
  t: ReturnType<typeof useTranslator>,
): string {
  switch (issue) {
    case 'query':
      return t('usersFilterQueryTooLong')
    case 'username':
      return t('usersFilterUsernameTooLong')
    case 'email':
      return t('usersFilterEmailTooLong')
    case 'createdFrom':
    case 'createdBefore':
      return t('usersFilterDateInvalid')
    case 'createdRange':
      return t('usersFilterDateRange')
  }
}

const USERS_ADVANCED_FILTERS_ID = 'users-advanced-filters'

function isAdvancedIssue(issue: UsersSearchIssue): boolean {
  return issue !== 'query'
}

function advancedFilterCount(draft: UsersFilterDraft): number {
  return [
    draft.username.trim().length > 0,
    draft.email.trim().length > 0,
    draft.enabled !== 'any',
    draft.locked !== 'any',
    draft.createdFrom.trim().length > 0,
    draft.createdBefore.trim().length > 0,
  ].filter(Boolean).length
}

function UsersFilters({
  draft,
  issues,
  onChange,
  onStatusChange,
  onApply,
  onReset,
}: {
  draft: UsersFilterDraft
  issues: ReadonlyArray<UsersSearchIssue>
  onChange: (
    key: 'q' | 'username' | 'email' | 'createdFrom' | 'createdBefore',
    value: string,
  ) => void
  onStatusChange: (key: 'enabled' | 'locked', value: string) => void
  onApply: () => void
  onReset: () => void
}) {
  const t = useTranslator()
  const has = (issue: UsersSearchIssue) => issues.includes(issue)
  const advancedCount = advancedFilterCount(draft)
  const advancedInvalid = issues.some(isAdvancedIssue)
  const [advancedExpanded, setAdvancedExpanded] = useState(
    () => advancedCount > 0 || advancedInvalid,
  )

  useEffect(() => {
    if (advancedInvalid) setAdvancedExpanded(true)
  }, [advancedInvalid])

  return (
    <div className="collection-filters">
      <form
        aria-label={t('usersFiltersTitle')}
        onSubmit={(event) => {
          event.preventDefault()
          onApply()
        }}
        noValidate
      >
        <div className="collection-filter-controls flex flex-col gap-3 lg:flex-row lg:items-end">
          <div className="min-w-0 flex-1">
            <UserTextField
              name="q"
              label={t('usersFilterSearchLabel')}
              value={draft.q}
              onChange={(value) => onChange('q', value)}
              placeholder={t('usersFilterSearchPlaceholder')}
              error={has('query') ? t('usersFilterQueryTooLong') : undefined}
              maxLength={256}
            />
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end lg:shrink-0">
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit">
                <Search className="size-4" aria-hidden="true" />
                {t('usersApplyFilters')}
              </Button>
              <Button type="button" variant="secondary" onPress={onReset}>
                <RotateCcw className="size-4" aria-hidden="true" />
                {t('usersResetFilters')}
              </Button>
            </div>
          </div>
        </div>
        <div className="mt-4 border-t border-separator pt-3">
          <Disclosure
            isExpanded={advancedExpanded}
            onExpandedChange={setAdvancedExpanded}
          >
            <Disclosure.Trigger
              type="button"
              aria-expanded={advancedExpanded}
              aria-controls={USERS_ADVANCED_FILTERS_ID}
              className="inline-flex w-fit items-center gap-2 rounded-field px-2 py-1.5 text-sm font-medium text-foreground transition-colors hover:bg-surface-secondary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
            >
              <span>
                {advancedExpanded
                  ? t('usersAdvancedFiltersHide')
                  : t('usersAdvancedFiltersShow')}
              </span>
              {advancedCount > 0 ? (
                <span className="rounded-full bg-surface-secondary px-2 py-0.5 text-xs font-medium text-muted">
                  {t('usersAdvancedFiltersActive', {
                    count: advancedCount,
                  })}
                </span>
              ) : null}
              <Disclosure.Indicator className="size-4 shrink-0 text-muted" />
            </Disclosure.Trigger>
            <Disclosure.Content id={USERS_ADVANCED_FILTERS_ID} role="region">
              <Disclosure.Body className="pt-3">
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                  <UserTextField
                    name="username"
                    label={t('usersFilterUsernameLabel')}
                    value={draft.username}
                    onChange={(value) => onChange('username', value)}
                    error={
                      has('username')
                        ? t('usersFilterUsernameTooLong')
                        : undefined
                    }
                    maxLength={65}
                  />
                  <UserTextField
                    name="email"
                    label={t('usersFilterEmailLabel')}
                    value={draft.email}
                    onChange={(value) => onChange('email', value)}
                    type="email"
                    error={
                      has('email') ? t('usersFilterEmailTooLong') : undefined
                    }
                    maxLength={321}
                  />
                  <UserSelectField
                    name="enabled"
                    label={t('usersFilterEnabledLabel')}
                    value={draft.enabled}
                    onChange={(value) => onStatusChange('enabled', value)}
                    options={[
                      { id: 'any', label: t('usersFilterAny') },
                      { id: 'true', label: t('usersFilterEnabledOnly') },
                      { id: 'false', label: t('usersFilterDisabledOnly') },
                    ]}
                  />
                  <UserSelectField
                    name="locked"
                    label={t('usersFilterLockedLabel')}
                    value={draft.locked}
                    onChange={(value) => onStatusChange('locked', value)}
                    options={[
                      { id: 'any', label: t('usersFilterAny') },
                      { id: 'true', label: t('usersFilterLockedOnly') },
                      { id: 'false', label: t('usersFilterUnlockedOnly') },
                    ]}
                  />
                  <DatePickerField
                    name="createdFrom"
                    label={t('usersFilterCreatedFromLabel')}
                    value={draft.createdFrom}
                    onChange={(value) => onChange('createdFrom', value)}
                    error={
                      has('createdFrom')
                        ? t('usersFilterDateInvalid')
                        : undefined
                    }
                  />
                  <DatePickerField
                    name="createdBefore"
                    label={t('usersFilterCreatedBeforeLabel')}
                    value={draft.createdBefore}
                    onChange={(value) => onChange('createdBefore', value)}
                    error={
                      has('createdRange')
                        ? t('usersFilterDateRange')
                        : has('createdBefore')
                          ? t('usersFilterDateInvalid')
                          : undefined
                    }
                  />
                </div>
                <p className="mt-3 text-xs leading-5 text-muted">
                  {t('usersFilterDateHint')}
                </p>
              </Disclosure.Body>
            </Disclosure.Content>
          </Disclosure>
        </div>
        {issues.length > 0 ? (
          <div className="mt-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('usersFilterInvalidTitle')}</Alert.Title>
                <Alert.Description>
                  {t('usersFilterInvalidDescription')}
                </Alert.Description>
                <ul className="mt-2 list-inside list-disc text-xs">
                  {issues.map((issue) => (
                    <li key={issue}>{issueMessage(issue, t)}</li>
                  ))}
                </ul>
              </Alert.Content>
            </Alert>
          </div>
        ) : null}
      </form>
    </div>
  )
}

export function UsersListPage({ search }: { search: UsersSearch }) {
  const { timeZone } = useLocale()
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions ?? null
  const scope = useMemo(() => userManagementScope(permissions), [permissions])
  const searchKey = usersSearchKey(search)
  const [draft, setDraft] = useState<UsersFilterDraft>(() =>
    usersFilterDraft(search),
  )
  const [localIssues, setLocalIssues] = useState<UsersSearchIssue[]>([])

  useEffect(() => {
    setDraft(usersFilterDraft(search))
    setLocalIssues([])
  }, [searchKey])

  const urlIssues = usersSearchIssues(search)
  const issues = localIssues.length > 0 ? localIssues : urlIssues
  const variables = useMemo(
    () => usersQueryVariables(search, timeZone),
    [searchKey, timeZone],
  )
  const users = useUsers(variables, Boolean(scope.read && variables))

  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      void navigate({
        to: '/users',
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
  })

  const header = (
    <PageHeader
      title={t('usersTitle')}
      description={t('usersDescription')}
      actions={
        scope.create && scope.read ? (
          <Button onPress={() => void navigate({ to: '/users/new' })}>
            <Plus className="size-4" aria-hidden="true" />
            {t('usersNewAction')}
          </Button>
        ) : undefined
      }
    />
  )

  if (workspace.status === 'idle' || workspace.status === 'loading') {
    return (
      <>
        {header}
        <AsyncState kind="loading" title={t('loading')} />
      </>
    )
  }

  if (workspace.status === 'error' && !permissions) {
    return (
      <>
        {header}
        {workspace.stepUp ? (
          <StepUpPanel
            stepUp={workspace.stepUp}
            hideDetails
            description={t('usersStepUpDescription')}
            note={t('usersStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={workspace.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(workspace.failure, workspace.forbidden))}
            description={t(
              failureDescriptionKey(workspace.failure, workspace.forbidden),
            )}
            requestId={workspace.requestId}
            traceId={workspace.traceId}
            issues={workspace.errors}
            onRetry={() => void workspace.refresh()}
          />
        )}
      </>
    )
  }

  if (!permissions) {
    return (
      <>
        {header}
        <AsyncState
          kind={workspace.forbidden ? 'forbidden' : 'partial'}
          title={t(
            workspace.forbidden
              ? failureTitleKey(workspace.failure, true)
              : 'partialTitle',
          )}
          description={t(
            workspace.forbidden
              ? failureDescriptionKey(workspace.failure, true)
              : 'partialDescription',
          )}
          requestId={workspace.requestId}
          traceId={workspace.traceId}
          issues={workspace.errors}
          onRetry={() => void workspace.refresh()}
        />
      </>
    )
  }

  if (!scope.hasAny && false) {
    return (
      <>
        {header}
        <StepUpPanel
          stepUp={{ source: 'graphql', acrValues: 'aal2' }}
          hideDetails
          description={t('usersStepUpDescription')}
          note={t('usersStepUpNote')}
        />
      </>
    )
  }

  if (!scope.hasAny || !scope.read) {
    return (
      <>
        {header}
        <UserReadRestricted
          scope={scope}
          onCreate={() => void navigate({ to: '/users/new' })}
          onGoHome={() => void navigate({ to: '/' })}
        />
      </>
    )
  }

  function changeDraft(
    key: 'q' | 'username' | 'email' | 'createdFrom' | 'createdBefore',
    value: string,
  ) {
    setDraft((current) => ({ ...current, [key]: value }))
    setLocalIssues([])
  }

  function changeStatus(key: 'enabled' | 'locked', value: string) {
    if (value !== 'any' && value !== 'true' && value !== 'false') return
    setDraft((current) => ({ ...current, [key]: value }))
    setLocalIssues([])
  }

  function applyFilters() {
    const next = usersSearchFromDraft(draft)
    const nextIssues = usersSearchIssues(next)
    if (nextIssues.length > 0) {
      setLocalIssues(nextIssues)
      return
    }
    setLocalIssues([])
    void navigate({ to: '/users', search: next })
  }

  function resetFilters() {
    setDraft(emptyUsersFilterDraft())
    setLocalIssues([])
    void navigate({ to: '/users', search: {} })
  }

  function renderList() {
    if (issues.length > 0) {
      return (
        <AsyncState
          kind="empty"
          title={t('usersFilterInvalidTitle')}
          description={t('usersFilterInvalidDescription')}
        />
      )
    }

    if (users.stepUp && users.status === 'error') {
      return (
        <StepUpPanel
          stepUp={users.stepUp}
          hideDetails
          description={t('usersStepUpDescription')}
          note={t('usersStepUpNote')}
        />
      )
    }

    if (users.status === 'error') {
      return (
        <AsyncState
          kind={users.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(users.failure, users.forbidden))}
          description={t(failureDescriptionKey(users.failure, users.forbidden))}
          requestId={users.requestId}
          traceId={users.traceId}
          issues={users.errors}
          onRetry={() => void users.refresh()}
        />
      )
    }

    if (users.status !== 'ready' || !users.data) {
      return <UsersTableLoading />
    }

    const edges = users.data.edges ?? []
    const emptyState = (() => {
      if (edges.length === 0) {
        if (hasUserFilters(search) || Boolean(search.after || search.before)) {
          return (
            <AsyncState
              kind="empty"
              title={t('usersNoResultsTitle')}
              description={t('usersNoResultsDescription')}
              action={
                <Button variant="secondary" onPress={resetFilters}>
                  {t('usersClearFilters')}
                </Button>
              }
            />
          )
        }
        return (
          <AsyncState
            kind="empty"
            title={t('usersEmptyTitle')}
            description={t('usersEmptyDescription')}
            action={
              scope.create ? (
                <Button onPress={() => void navigate({ to: '/users/new' })}>
                  <Plus className="size-4" aria-hidden="true" />
                  {t('usersNewAction')}
                </Button>
              ) : undefined
            }
          />
        )
      }
      return undefined
    })()

    const pageInfo = users.data.pageInfo

    return (
      <div className="space-y-4">
        {users.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('usersPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('usersPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={users.requestId}
                traceId={users.traceId}
              />
              <ErrorDetails issues={users.errors} />
            </Alert.Content>
          </Alert>
        ) : null}

        <UsersTable
          emptyState={emptyState}
          users={edges.map((edge) => edge.node)}
          canEdit={scope.update}
          order={search.order}
          onOrderChange={(order) => {
            if (order === undefined || isUserOrder(order))
              void navigate({
                to: '/users',
                search: {
                  ...search,
                  order,
                  after: undefined,
                  before: undefined,
                },
              })
          }}
          refreshing={users.refreshing}
          onRefresh={() => void users.refresh()}
          pagination={
            <CursorPagination
              label={t('usersPaginationLabel')}
              pageCount={edges.length}
              totalCount={users.data.totalCount}
              pageInfo={pageInfo}
              controller={pager}
              isDisabled={users.refreshing}
            />
          }
        />
      </div>
    )
  }

  return (
    <>
      {header}
      <UsersFilters
        draft={draft}
        issues={issues}
        onChange={changeDraft}
        onStatusChange={changeStatus}
        onApply={applyFilters}
        onReset={resetFilters}
      />
      {renderList()}
    </>
  )
}
