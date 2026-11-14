import { TableRowActions } from '#/components/table-row-actions'
import { CursorPagination } from '#/components/cursor-pagination'
import { DatePickerField } from '#/components/date-picker-field'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useUrlFilters } from '#/lib/use-url-filters'
import {
  CollectionToolbar,
  ResourceTable,
  type ResourceTableControls,
} from '#/components/resource-table'
import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Link, useNavigate } from '@tanstack/react-router'
import { ChevronDown, Plus, TriangleAlert } from 'lucide-react'
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
  USERS_PAGE_SIZE,
  hasUserFilters,
  isUserOrder,
  usersAppliedFilters,
  usersFilterDraft,
  usersFormSearch,
  usersQueryVariables,
  usersSearchIssues,
  usersSearchKey,
  type UsersFilterDraft,
  type UsersFilters,
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
                    className="block truncate font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                  >
                    {user.username}
                  </Link>
                  <p
                    className="mt-0.5 truncate text-xs text-muted-foreground"
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
      className="space-y-3 rounded-lg border border-border bg-card p-4"
      role="status"
      aria-live="polite"
      aria-label={t('usersTableLoading')}
    >
      <span className="sr-only">{t('usersTableLoading')}</span>
      <Skeleton className="h-10 w-full rounded-lg" />
      {Array.from({ length: 5 }, (_, index) => (
        <Skeleton key={index} className="h-14 w-full rounded-lg" />
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
    case 'createdTo':
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
    draft.createdTo.trim().length > 0,
  ].filter(Boolean).length
}

function UsersFilterBar({
  draft,
  issues,
  onChange,
  onApply,
  onReset,
  advancedExpanded,
  onAdvancedToggle,
}: {
  draft: UsersFilterDraft
  issues: ReadonlyArray<UsersSearchIssue>
  onChange: (key: 'q', value: string) => void
  onApply: () => void
  onReset: () => void
  advancedExpanded: boolean
  onAdvancedToggle: () => void
}) {
  const t = useTranslator()
  const advancedCount = advancedFilterCount(draft)
  return (
    <form
      aria-label={t('usersFiltersTitle')}
      onSubmit={(event) => {
        event.preventDefault()
        onApply()
      }}
      noValidate
      className="flex flex-wrap items-start gap-2"
    >
      <div className="w-full sm:w-72">
        <UserTextField
          name="q"
          label={t('usersFilterSearchLabel')}
          hideLabel
          value={draft.q}
          onChange={(value) => onChange('q', value)}
          placeholder={t('usersFilterSearchPlaceholder')}
          error={
            issues.includes('query') ? t('usersFilterQueryTooLong') : undefined
          }
          maxLength={256}
        />
      </div>
      <Button type="submit" variant="outline">
        {t('usersApplyFilters')}
      </Button>
      <Button type="button" variant="ghost" onClick={onReset}>
        {t('usersResetFilters')}
      </Button>
      <Button
        type="button"
        variant="ghost"
        aria-expanded={advancedExpanded}
        aria-controls={USERS_ADVANCED_FILTERS_ID}
        onClick={onAdvancedToggle}
      >
        {t('usersAdvancedFilters')}
        {advancedCount > 0 ? (
          <>
            <Badge
              variant="secondary"
              // The highlighted button shares the badge's fill; outline it then.
              className="min-w-5 px-1.5 tabular-nums group-hover/button:border-border group-aria-expanded/button:border-border"
              aria-hidden="true"
            >
              {advancedCount}
            </Badge>
            <span className="sr-only">
              {t('usersAdvancedFiltersActive', { count: advancedCount })}
            </span>
          </>
        ) : null}
        <ChevronDown
          className={`text-muted-foreground transition-transform ${advancedExpanded ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </Button>
    </form>
  )
}

/** Full-width panel under the toolbar row: advanced fields and filter issues. */
function UsersAdvancedFilters({
  draft,
  issues,
  expanded,
  onChange,
  onStatusChange,
  onApply,
}: {
  draft: UsersFilterDraft
  issues: ReadonlyArray<UsersSearchIssue>
  expanded: boolean
  onChange: (
    key: 'username' | 'email' | 'createdFrom' | 'createdTo',
    value: string,
  ) => void
  onStatusChange: (key: 'enabled' | 'locked', value: string) => void
  onApply: () => void
}) {
  const t = useTranslator()
  const has = (issue: UsersSearchIssue) => issues.includes(issue)
  if (!expanded && issues.length === 0) return null
  return (
    <div className="flex flex-col gap-3">
      {expanded ? (
        <form
          id={USERS_ADVANCED_FILTERS_ID}
          aria-label={t('usersAdvancedFilters')}
          onSubmit={(event) => {
            event.preventDefault()
            onApply()
          }}
          noValidate
          className="rounded-lg border border-border p-4"
        >
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
              name="createdTo"
              label={t('usersFilterCreatedToLabel')}
              value={draft.createdTo}
              onChange={(value) => onChange('createdTo', value)}
              error={
                has('createdRange')
                  ? t('usersFilterDateRange')
                  : has('createdTo')
                    ? t('usersFilterDateInvalid')
                    : undefined
              }
            />
          </div>
        </form>
      ) : null}
      {issues.length > 0 ? (
        <div>
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>{t('usersFilterInvalidTitle')}</AlertTitle>
            <AlertDescription>
              {t('usersFilterInvalidDescription')}
            </AlertDescription>
            <ul className="mt-2 list-inside list-disc text-xs">
              {issues.map((issue) => (
                <li key={issue}>{issueMessage(issue, t)}</li>
              ))}
            </ul>
          </Alert>
        </div>
      ) : null}
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
  // The URL always mirrors the filter form; queries use only the filters
  // last applied. Editing a field rewrites the URL without sending anything.
  const draft = usersFilterDraft(search)
  const { applied, go } = useUrlFilters<UsersSearch, UsersFilters>({
    search,
    keyOf: usersSearchKey,
    appliedOf: usersAppliedFilters,
    navigate: (next, { replace }) =>
      void navigate({ to: '/users', search: next, replace }),
  })

  const appliedSearch: UsersSearch = {
    ...applied,
    order: search.order,
    size: search.size,
    after: search.after,
    before: search.before,
  }
  const appliedKey = usersSearchKey(appliedSearch)
  // Field messages follow the form; the list reports only what was applied.
  const issues = usersSearchIssues(search)
  const appliedIssues = usersSearchIssues(appliedSearch)
  const advancedInvalid = issues.some(isAdvancedIssue)
  const [advancedExpanded, setAdvancedExpanded] = useState(
    () => advancedFilterCount(usersFilterDraft(search)) > 0 || advancedInvalid,
  )
  useEffect(() => {
    if (advancedInvalid) setAdvancedExpanded(true)
  }, [advancedInvalid])
  const variables = useMemo(
    () => usersQueryVariables(appliedSearch, timeZone),
    [appliedKey, timeZone],
  )
  const users = useUsers(variables, Boolean(scope.read && variables))

  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      go({
        ...search,
        after: undefined,
        before: undefined,
        ...cursor,
      }),
  })

  const header = (
    <PageHeader
      title={t('usersTitle')}
      description={t('usersDescription')}
      actions={
        scope.create && scope.read ? (
          <Button onClick={() => void navigate({ to: '/users/new' })}>
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

  function changeForm(next: UsersFilterDraft) {
    go({ ...search, ...usersFormSearch(next) }, { replace: true })
  }

  function changeDraft(
    key: 'q' | 'username' | 'email' | 'createdFrom' | 'createdTo',
    value: string,
  ) {
    changeForm({ ...draft, [key]: value })
  }

  function changeStatus(key: 'enabled' | 'locked', value: string) {
    if (value !== 'any' && value !== 'true' && value !== 'false') return
    changeForm({ ...draft, [key]: value })
  }

  function applyFilters() {
    const filters = usersAppliedFilters(search)
    if (usersSearchIssues({ ...search, ...filters }).length > 0) return
    const next: UsersSearch = {
      ...search,
      ...filters,
      after: undefined,
      before: undefined,
    }
    // Applying the filters already in effect on the first page reloads them.
    if (usersSearchKey(next) === appliedKey) void users.refresh()
    go(next, { apply: filters })
  }

  function resetFilters() {
    go({ size: search.size }, { apply: {} })
  }

  const filters = (
    <UsersFilterBar
      draft={draft}
      issues={issues}
      onChange={changeDraft}
      onApply={applyFilters}
      onReset={resetFilters}
      advancedExpanded={advancedExpanded}
      onAdvancedToggle={() => setAdvancedExpanded((open) => !open)}
    />
  )
  const filtersPanel = (
    <UsersAdvancedFilters
      draft={draft}
      issues={issues}
      expanded={advancedExpanded}
      onChange={changeDraft}
      onStatusChange={changeStatus}
      onApply={applyFilters}
    />
  )

  function renderList() {
    const toolbar = <CollectionToolbar filters={filters} panel={filtersPanel} />
    if (appliedIssues.length > 0) {
      return (
        <>
          {toolbar}
          <AsyncState
            kind="empty"
            title={t('usersFilterInvalidTitle')}
            description={t('usersFilterInvalidDescription')}
          />
        </>
      )
    }

    if (users.stepUp && users.status === 'error') {
      return (
        <>
          {toolbar}
          <StepUpPanel
            stepUp={users.stepUp}
            hideDetails
            description={t('usersStepUpDescription')}
            note={t('usersStepUpNote')}
          />
        </>
      )
    }

    if (users.status === 'error') {
      return (
        <>
          {toolbar}
          <AsyncState
            kind={users.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(users.failure, users.forbidden))}
            description={t(failureDescriptionKey(users.failure, users.forbidden))}
            requestId={users.requestId}
            traceId={users.traceId}
            issues={users.errors}
            onRetry={() => void users.refresh()}
          />
        </>
      )
    }

    if (users.status !== 'ready' || !users.data) {
      return (
        <>
          {toolbar}
          <UsersTableLoading />
        </>
      )
    }

    const edges = users.data.edges ?? []
    const emptyState = (() => {
      if (edges.length === 0) {
        if (
          hasUserFilters(appliedSearch) ||
          Boolean(search.after || search.before)
        ) {
          return (
            <AsyncState
              kind="empty"
              compact
              title={t('usersNoResultsTitle')}
              description={t('usersNoResultsDescription')}
              action={
                <Button variant="outline" onClick={resetFilters}>
                  {t('usersClearFilters')}
                </Button>
              }
            />
          )
        }
        return (
          <AsyncState
            kind="empty"
            compact
            title={t('usersEmptyTitle')}
            description={t('usersEmptyDescription')}
            action={
              scope.create ? (
                <Button onClick={() => void navigate({ to: '/users/new' })}>
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
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>{t('usersPartialTitle')}</AlertTitle>
            <AlertDescription>{t('usersPartialDescription')}</AlertDescription>
            <RequestCorrelation
              requestId={users.requestId}
              traceId={users.traceId}
            />
            <ErrorDetails issues={users.errors} />
          </Alert>
        ) : null}

        <UsersTable
          filters={filters}
          filtersPanel={filtersPanel}
          emptyState={emptyState}
          users={edges.map((edge) => edge.node)}
          canEdit={scope.update}
          order={search.order}
          onOrderChange={(order) => {
            if (order === undefined || isUserOrder(order))
              go({
                ...search,
                order,
                after: undefined,
                before: undefined,
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
              pageSize={search.size ?? USERS_PAGE_SIZE}
              onPageSizeChange={(size) =>
                go({
                  ...search,
                  size,
                  after: undefined,
                  before: undefined,
                })
              }
            />
          }
        />
      </div>
    )
  }

  return (
    <>
      {header}
      {renderList()}
    </>
  )
}
