import { EditRolesDialog } from '../components/edit-group-roles-dialog'
import { RelationPagination } from '../../components/relation-picker'

import { DataTable } from '@identity/ui/data-table'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Badge } from '@identity/ui/components/badge'
import { Link, useNavigate } from '@tanstack/react-router'
import { Info, TriangleAlert } from 'lucide-react'

import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { CollectionToolbar } from '#/components/resource-table'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import { type ConsoleGroupRolesQueryVariables } from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { useGroupRoles } from '#/modules/user-management/groups/hooks/use-group-roles'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'

import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { AssignmentStatusChip } from '#/modules/user-management/roles/components/role-status'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'


type RelationStatus = 'any' | 'enabled' | 'disabled'

export function GroupRolesPage({ groupId }: { groupId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const canRead = scope.groupsRead && scope.groupRolesRead && scope.rolesRead
  const [status, setStatus] = useState<RelationStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [pageSize, setPageSize] = useState(10)
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const variables = useMemo<ConsoleGroupRolesQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'ROLE_NAME_ASC',
            ...cursorPage(pageSize, after, before),
          }
        : null,
    [after, before, canRead, groupId, status, pageSize],
  )
  const roles = useGroupRoles(variables)
  const group = roles.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead
              ? 'groupsNoReadTitle'
              : !scope.groupRolesRead
                ? 'groupRolesNoReadTitle'
                : 'rolesNoReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : !scope.groupRolesRead
                ? 'groupRolesNoReadDescription'
                : 'rolesNoReadDescription'
          }

          onBack={() => void navigate({ to: '/groups' })}
          backLabel="backToGroups"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roles.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {roles.stepUp ? (
          <StepUpPanel
            stepUp={roles.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={roles.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(roles.failure, roles.forbidden))}
            description={t(
              failureDescriptionKey(roles.failure, roles.forbidden),
            )}
            requestId={roles.requestId}
            traceId={roles.traceId}
            issues={roles.errors}
            onRetry={() => void roles.refresh()}
          />
        )}
      </ConsoleWorkspaceGate>
    )
  }

  if (roles.status === 'ready' && !group) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState
          kind="notFound"
          title={t('notFoundTitle')}
          description={t('notFoundDescription')}
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roles.status !== 'ready' || !group) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const readyGroup = group
  const groupName =
    resolveLocalizedText(readyGroup.names, locale) ??
    readyGroup.name ??
    readyGroup.id
  const normalizedSearch = search.trim().toLowerCase()
  const edges = readyGroup.roles.edges.filter(({ node: role }) => {
    if (!normalizedSearch) return true
    const name = resolveLocalizedText(role.names, locale) ?? role.name
    return [name, role.id]
      .join(' ')
      .toLowerCase()
      .includes(normalizedSearch)
  })

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}

        {readyGroup.builtIn ? (
          <Alert>
            <Info aria-hidden="true" />
            <AlertTitle>{t('groupRolesBuiltInTitle')}</AlertTitle>
            <AlertDescription>
              {t('groupRolesBuiltInDescription')}
            </AlertDescription>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupRolesListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('groupRolesListDescription')}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {!readyGroup.builtIn &&
              scope.rolesRead &&
              scope.groupRolesWrite ? (
                <EditRolesDialog
                  groupId={readyGroup.id}
                  groupVersion={readyGroup.version}
                  groupName={groupName}
                  onSaved={(addedCount, removedCount) => {
                    setNotice({
                      kind: 'success',
                      title: t('groupRolesSavedToast'),
                      description: t('groupRolesSavedCommitted', {
                        addedCount,
                        removedCount,
                      }),
                    })
                  }}
                  onReload={() => void roles.refresh()}
                  reloadPending={roles.refreshing}
                />
              ) : null}
            </div>
          </header>
          <CollectionToolbar
            filters={
              <div className="flex flex-wrap items-start gap-2">
                <div className="w-full sm:w-72">
                  <UserTextField
                    name="group-role-search"
                    label={t('groupRolesSearchLabel')}
                    hideLabel
                    value={search}
                    onChange={setSearch}
                    placeholder={t('groupRolesSearchPlaceholder')}
                    maxLength={256}
                  />
                </div>
                <div className="w-36">
                  <UserSelectField
                    name="group-role-status"
                    label={t('groupRolesFilterStatusLabel')}
                    hideLabel
                    value={status}
                    onChange={(value) => {
                      if (
                        value === 'any' ||
                        value === 'enabled' ||
                        value === 'disabled'
                      ) {
                        setStatus(value)
                        setAfter(undefined)
                        setBefore(undefined)
                      }
                    }}
                    options={[
                      { id: 'any', label: t('groupRolesFilterAll') },
                      { id: 'enabled', label: t('groupRolesFilterActive') },
                      { id: 'disabled', label: t('groupRolesFilterRemoved') },
                    ]}
                  />
                </div>
              </div>
            }
          />
          <div className="p-0">
            {roles.partial ? (
              <div className="p-3">
                <Alert variant="default" className="text-warning">
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>{t('groupsPartialTitle')}</AlertTitle>
                  <AlertDescription>
                    {t('groupsPartialDescription')}
                  </AlertDescription>
                  <RequestCorrelation
                    requestId={roles.requestId}
                    traceId={roles.traceId}
                  />
                  <ErrorDetails issues={roles.errors} />
                </Alert>
              </div>
            ) : null}
            <DataTable
              label={t('groupRolesTableLabel')}
              minWidth={820}
              columns={[
                {
                  id: 'groupRolesColumnRole',
                  label: t('groupRolesColumnRole'),
                  primary: true,
                },
                {
                  id: 'groupRolesColumnRelation',
                  label: t('groupRolesColumnRelation'),
                  primary: false,
                },
              ]}
            >
              <DataTable.Body
                renderEmptyState={() =>
                  readyGroup.roles.edges.length === 0 ? (
                    <AsyncState
                      kind="empty"
                      compact
                      title={
                        status === 'any'
                          ? t('groupRolesEmptyTitle')
                          : t('groupRolesEmptyFilteredTitle')
                      }
                      description={
                        status === 'any'
                          ? t('groupRolesEmptyDescription')
                          : t('groupRolesEmptyFilteredDescription')
                      }
                    />
                  ) : (
                    <AsyncState
                      kind="empty"
                      compact
                      title={t('groupRolesSearchNoMatches')}
                      description={t('groupRolesSearchDescription')}
                    />
                  )
                }
              >
                {edges.map((edge) => {
                  const role = edge.node
                  const name =
                    resolveLocalizedText(role.names, locale) ?? role.name
                  return (
                    <DataTable.Row key={role.id} id={role.id}>
                      <DataTable.Cell>
                        <div className="min-w-56">
                          <Link
                            to="/roles/$roleId"
                            params={{ roleId: role.id }}
                            className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                          >
                            {name}
                          </Link>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {role.builtIn ? (
                              <Badge
                                variant="secondary"
                                className="text-primary"
                              >
                                {t('groupRolesBuiltInRoleLabel')}
                              </Badge>
                            ) : null}
                            {!role.enabled ? (
                              <Badge
                                variant="secondary"
                                className="text-warning"
                              >
                                {t('rolesDisabled')}
                              </Badge>
                            ) : null}
                          </div>
                        </div>
                      </DataTable.Cell>
                      <DataTable.Cell>
                        <AssignmentStatusChip
                          enabled={edge.enabled}
                          revokedAt={edge.revokedAt}
                          roleEnabled={role.enabled}
                        />
                      </DataTable.Cell>
                    </DataTable.Row>
                  )
                })}
              </DataTable.Body>
            </DataTable>
          </div>
          <footer className="resource-collection-pagination">
            <RelationPagination
              connection={readyGroup.roles}
              variables={variables}
              after={after}
              before={before}
              onNavigate={(page) => {
                setAfter(page.after)
                setBefore(page.before)
              }}
              label={t('roleUsersPagination')}
              isDisabled={roles.refreshing || roles.status !== 'ready'}
              pageSize={pageSize}
              onPageSizeChange={(size) => {
                setPageSize(size)
                setAfter(undefined)
                setBefore(undefined)
              }}
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )
}
