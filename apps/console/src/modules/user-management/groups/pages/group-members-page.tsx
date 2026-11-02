import { RelationPagination } from '../../components/relation-picker'
import {
  AddMemberDialog,
  RemoveMemberDialog,
} from '../components/membership-dialogs'

import { DataTable } from '@identity/ui/data-table'
import { Alert, Chip } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'

import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  type ConsoleGroupMembersQuery,
  type ConsoleGroupMembersQueryVariables,
} from '#/gql/graphql'
import { formatDateTime } from '#/lib/format'
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
import { useGroupMembers } from '#/modules/user-management/groups/hooks/use-group-members'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'

import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 10

type GroupNode = NonNullable<ConsoleGroupMembersQuery['group']>
type MemberNode = GroupNode['members']['edges'][number]['node']
type MemberStatus = 'any' | 'enabled' | 'disabled'

export function GroupMembersPage({ groupId }: { groupId: string }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const canRead = scope.groupsRead && scope.groupMembershipsRead
  const [status, setStatus] = useState<MemberStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const variables = useMemo<ConsoleGroupMembersQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeUser: scope.usersRead,
          }
        : null,
    [after, before, canRead, groupId, scope.usersRead, status],
  )
  const members = useGroupMembers(variables)
  const group = members.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead ? 'groupsNoReadTitle' : 'groupMembersNoReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : 'groupMembersNoReadDescription'
          }

          onBack={() => void navigate({ to: '/groups' })}
          backLabel="backToGroups"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (members.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {members.stepUp ? (
          <StepUpPanel
            stepUp={members.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={members.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(members.failure, members.forbidden))}
            description={t(
              failureDescriptionKey(members.failure, members.forbidden),
            )}
            requestId={members.requestId}
            traceId={members.traceId}
            issues={members.errors}
            onRetry={() => void members.refresh()}
          />
        )}
      </ConsoleWorkspaceGate>
    )
  }

  if (members.status === 'ready' && !group) {
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

  if (members.status !== 'ready' || !group) {
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
              <Alert.Title>{t('groupBuiltInReadonlyTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupMembersBuiltInNote')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        {scope.usersRead ? null : (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupMembersNoUsersReadTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupMembersNoUsersReadDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        )}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupMembersListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted">
                {t('groupMembersListDescription')}
              </p>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-44">
                <UserSelectField
                  name="group-member-status"
                  label={t('groupMembersStatusFilterLabel')}
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
                    { id: 'any', label: t('groupMembersFilterAll') },
                    { id: 'enabled', label: t('groupMembersFilterActive') },
                    { id: 'disabled', label: t('groupMembersFilterRemoved') },
                  ]}
                />
              </div>
              {scope.groupMembershipsWrite && scope.usersRead ? (
                <AddMemberDialog
                  groupId={readyGroup.id}
                  groupVersion={readyGroup.version}
                  groupName={groupName}
                  onAdded={() => {
                    setNotice({
                      kind: 'success',
                      title: t('groupMembersAddedToast'),
                      description: t('groupMembersAddedCommitted'),
                    })
                    void members.refresh()
                  }}
                  onReload={() => void members.refresh()}
                  reloadPending={members.refreshing}
                />
              ) : null}
            </div>
          </header>
          <div className="p-0">{renderMembers()}</div>
          <footer className="border-t border-separator pt-4">
            <RelationPagination
              connection={readyGroup.members}
              variables={variables}
              after={after}
              before={before}
              onNavigate={(page) => {
                setAfter(page.after)
                setBefore(page.before)
              }}
              label={t('roleUsersPagination')}
              isDisabled={members.refreshing || members.status !== 'ready'}
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )

  function renderMembers() {
    return (
      <>
        {members.partial ? (
          <div className="p-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
                <Alert.Description>
                  {t('groupsPartialDescription')}
                </Alert.Description>
                <RequestCorrelation
                  requestId={members.requestId}
                  traceId={members.traceId}
                />
                <ErrorDetails issues={members.errors} />
              </Alert.Content>
            </Alert>
          </div>
        ) : null}
        {renderMemberTable(readyGroup.members.edges)}
      </>
    )
  }

  function renderMemberTable(edges: GroupNode['members']['edges']) {
    if (edges.length === 0) {
      return (
        <div className="p-4">
          <AsyncState
            kind="empty"
            compact
            title={
              status === 'any'
                ? t('groupMembersEmptyTitle')
                : t('groupMembersEmptyFilteredTitle')
            }
            description={
              status === 'any'
                ? t('groupMembersEmptyDescription')
                : t('groupMembersEmptyFilteredDescription')
            }
          />
        </div>
      )
    }
    return (
      <DataTable
        label={t('groupMembersTableLabel')}
        minWidth={900}
        columns={[
          {
            id: 'groupMembersColumnMember',
            label: t('groupMembersColumnMember'),
            primary: true,
          },
          {
            id: 'groupMembersColumnStatus',
            label: t('groupMembersColumnStatus'),
            primary: false,
          },
          {
            id: 'groupMembersColumnCreated',
            label: t('groupMembersColumnCreated'),
            primary: false,
          },
          {
            id: 'groupMembersColumnActions',
            label: t('groupMembersColumnActions'),
            primary: false,
          },
        ]}
      >
        <DataTable.Body>
          {edges.map(({ node }) => (
            <DataTable.Row key={node.id} id={node.id}>
              <DataTable.Cell>{renderMemberIdentity(node)}</DataTable.Cell>
              <DataTable.Cell>
                {node.enabled && !node.revokedAt ? (
                  <Chip size="sm" variant="soft" color="success">
                    <Chip.Label>{t('groupMembersStatusActive')}</Chip.Label>
                  </Chip>
                ) : (
                  <Chip size="sm" variant="soft" color="default">
                    <Chip.Label>{t('groupMembersStatusRemoved')}</Chip.Label>
                  </Chip>
                )}
              </DataTable.Cell>
              <DataTable.Cell>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(node.createdAt, locale, timeZone)}
                </span>
                {node.revokedAt ? (
                  <span className="mt-0.5 block whitespace-nowrap text-xs text-muted">
                    {formatDateTime(node.revokedAt, locale, timeZone)}
                  </span>
                ) : null}
              </DataTable.Cell>
              <DataTable.Cell>
                {node.enabled && !node.revokedAt ? (
                  scope.groupMembershipsWrite ? (
                    <RemoveMemberDialog
                      node={node}
                      groupVersion={readyGroup.version}
                      onRemoved={() => {
                        setNotice({
                          kind: 'success',
                          title: t('groupMembersRemovedToast'),
                          description: t('groupMembersRemovedCommitted'),
                        })
                        void members.refresh()
                      }}
                      onReload={() => void members.refresh()}
                      reloadPending={members.refreshing}
                    />
                  ) : (
                    <span className="text-xs text-muted">
                      {t('groupMembersNoWritePermission')}
                    </span>
                  )
                ) : (
                  <span className="text-xs text-muted">
                    {t('groupMembersRevokedAt', {
                      date: formatDateTime(node.revokedAt, locale, timeZone),
                    })}
                  </span>
                )}
              </DataTable.Cell>
            </DataTable.Row>
          ))}
        </DataTable.Body>
      </DataTable>
    )
  }

  function renderMemberIdentity(node: MemberNode) {
    const user = scope.usersRead ? (node.user ?? null) : null
    return (
      <div className="min-w-52">
        {user ? (
          <>
            <Link
              to="/users/$userId"
              params={{ userId: user.id }}
              className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
            >
              {user.username}
            </Link>
            {user.email ? (
              <p className="mt-0.5 break-all text-xs text-muted">
                {user.email}
              </p>
            ) : null}
            <p className="mt-1 break-all font-mono text-[11px] text-muted">
              {t('groupMembersMembershipIdLabel')}: {node.id}
            </p>
          </>
        ) : (
          <>
            <p className="break-all font-mono text-xs">{node.userId}</p>
            <p className="mt-1 break-all font-mono text-[11px] text-muted">
              {t('groupMembersMembershipIdLabel')}: {node.id}
            </p>
            {scope.usersRead ? null : (
              <p className="mt-1 text-[11px] text-muted">
                {t('groupMembersUserHidden')}
              </p>
            )}
          </>
        )}
        {node.grantedByUserId ? (
          <p className="mt-1 break-all text-[11px] text-muted">
            {t('groupMembersGrantedByLabel')}: {node.grantedByUserId}
          </p>
        ) : null}
      </div>
    )
  }
}
