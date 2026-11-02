import { EditRolesDialog } from '../components/edit-group-roles-dialog'
import { RelationPagination } from '../../components/relation-picker'

import { DataTable } from '@identity/ui/data-table'
import { Alert, Chip } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'

import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import { type ConsoleGroupRolesQueryVariables } from '#/gql/graphql'
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
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 5

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
  const canRead = scope.groupsRead && scope.groupRolesRead
  const [status, setStatus] = useState<RelationStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const variables = useMemo<ConsoleGroupRolesQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'ROLE_NAME_ASC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeRole: scope.rolesRead,
          }
        : null,
    [after, before, canRead, groupId, scope.rolesRead, status],
  )
  const roles = useGroupRoles(variables)
  const group = roles.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead ? 'groupsNoReadTitle' : 'groupRolesNoReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : 'groupRolesNoReadDescription'
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
  const edges = readyGroup.roles.edges.filter(({ node }) => {
    if (!normalizedSearch) return true
    const role = scope.rolesRead ? (node.role ?? null) : null
    const name = role
      ? (resolveLocalizedText(role.names, locale) ?? role.name ?? role.id)
      : ''
    return [name, node.roleId, node.id]
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
          <Alert status="default">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupRolesBuiltInTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupRolesBuiltInDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        {!scope.rolesRead ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupRolesNoRoleReadTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupRolesNoRoleReadDescription')}
              </Alert.Description>
              {!readyGroup.builtIn ? (
                <p className="mt-2 text-xs text-muted">
                  {t('groupRolesSelectionNoRolesRead')}
                </p>
              ) : null}
            </Alert.Content>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupRolesListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted">
                {t('groupRolesListDescription')}
              </p>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-48">
                <UserTextField
                  name="group-role-search"
                  label={t('groupRolesSearchLabel')}
                  value={search}
                  onChange={setSearch}
                  placeholder={t('groupRolesSearchPlaceholder')}
                  maxLength={256}
                />
              </div>
              <div className="w-40">
                <UserSelectField
                  name="group-role-status"
                  label={t('groupRolesFilterStatusLabel')}
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
                    void roles.refresh()
                  }}
                  onReload={() => void roles.refresh()}
                  reloadPending={roles.refreshing}
                />
              ) : null}
            </div>
          </header>
          <div className="p-0">
            {roles.partial ? (
              <div className="p-3">
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
                    <Alert.Description>
                      {t('groupsPartialDescription')}
                    </Alert.Description>
                    <RequestCorrelation
                      requestId={roles.requestId}
                      traceId={roles.traceId}
                    />
                    <ErrorDetails issues={roles.errors} />
                  </Alert.Content>
                </Alert>
              </div>
            ) : null}
            {readyGroup.roles.edges.length === 0 ? (
              <div className="p-4">
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
              </div>
            ) : edges.length === 0 ? (
              <div className="p-4">
                <AsyncState
                  kind="empty"
                  compact
                  title={t('groupRolesSearchNoMatches')}
                  description={t('groupRolesSearchDescription')}
                />
              </div>
            ) : (
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
                <DataTable.Body>
                  {edges.map(({ node }) => {
                    const role = scope.rolesRead ? (node.role ?? null) : null
                    const name = role
                      ? (resolveLocalizedText(role.names, locale) ??
                        role.name ??
                        role.name ??
                        role.id)
                      : null
                    return (
                      <DataTable.Row key={node.id} id={node.id}>
                        <DataTable.Cell>
                          <div className="min-w-56">
                            {role && name ? (
                              <>
                                <Link
                                  to="/roles/$roleId"
                                  params={{ roleId: role.id }}
                                  className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
                                >
                                  {name}
                                </Link>
                                <div className="mt-1 flex flex-wrap gap-1">
                                  {role.builtIn ? (
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color="accent"
                                    >
                                      <Chip.Label>
                                        {t('groupRolesBuiltInRoleLabel')}
                                      </Chip.Label>
                                    </Chip>
                                  ) : null}
                                  {!role.enabled ? (
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color="warning"
                                    >
                                      <Chip.Label>
                                        {t('rolesDisabled')}
                                      </Chip.Label>
                                    </Chip>
                                  ) : null}
                                </div>
                              </>
                            ) : (
                              <>
                                <p className="break-all font-mono text-xs">
                                  {node.roleId}
                                </p>
                                <p className="mt-0.5 text-[11px] text-muted">
                                  {t('groupRolesRoleIdOnly')}
                                </p>
                              </>
                            )}
                          </div>
                        </DataTable.Cell>
                        <DataTable.Cell>
                          <BindingStatusChip
                            enabled={node.enabled}
                            revokedAt={node.revokedAt}
                            roleEnabled={role?.enabled}
                          />
                        </DataTable.Cell>
                      </DataTable.Row>
                    )
                  })}
                </DataTable.Body>
              </DataTable>
            )}
          </div>
          <footer className="border-t border-separator pt-4">
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
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )
}
