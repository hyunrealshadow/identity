import { RelationPagination } from '../../components/relation-picker'
import {
  AddMemberDialog,
  RemoveMemberDialog,
} from '../components/membership-dialogs'

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
import {
  type ConsoleGroupMembersQuery,
  type ConsoleGroupMembersQueryVariables,
} from '#/generated/graphql'
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


type GroupNode = NonNullable<ConsoleGroupMembersQuery['group']>
type MemberEdge = GroupNode['members']['edges'][number]
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
  const canRead =
    scope.groupsRead && scope.groupMembershipsRead && scope.usersRead
  const [status, setStatus] = useState<MemberStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [pageSize, setPageSize] = useState(10)
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const variables = useMemo<ConsoleGroupMembersQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(pageSize, after, before),
          }
        : null,
    [after, before, canRead, groupId, status, pageSize],
  )
  const members = useGroupMembers(variables)
  const group = members.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead
              ? 'groupsNoReadTitle'
              : !scope.groupMembershipsRead
                ? 'groupMembersNoReadTitle'
                : 'groupMembersNoUsersReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : !scope.groupMembershipsRead
                ? 'groupMembersNoReadDescription'
                : 'groupMembersNoUsersReadDescription'
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
          <Alert>
            <Info aria-hidden="true" />
            <AlertTitle>{t('groupBuiltInReadonlyTitle')}</AlertTitle>
            <AlertDescription>{t('groupMembersBuiltInNote')}</AlertDescription>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupMembersListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('groupMembersListDescription')}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {scope.groupMembershipsWrite ? (
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
                  }}
                  onReload={() => void members.refresh()}
                  reloadPending={members.refreshing}
                />
              ) : null}
            </div>
          </header>
          <CollectionToolbar
            filters={
              <div className="flex flex-wrap items-start gap-2">
                <div className="w-36">
                  <UserSelectField
                    name="group-member-status"
                    label={t('groupMembersStatusFilterLabel')}
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
                      { id: 'any', label: t('groupMembersFilterAll') },
                      { id: 'enabled', label: t('groupMembersFilterActive') },
                      { id: 'disabled', label: t('groupMembersFilterRemoved') },
                    ]}
                  />
                </div>
              </div>
            }
          />
          <div className="p-0">{renderMembers()}</div>
          <footer className="resource-collection-pagination">
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

  function renderMembers() {
    return (
      <>
        {members.partial ? (
          <div className="p-3">
            <Alert variant="default" className="text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{t('groupsPartialTitle')}</AlertTitle>
              <AlertDescription>
                {t('groupsPartialDescription')}
              </AlertDescription>
              <RequestCorrelation
                requestId={members.requestId}
                traceId={members.traceId}
              />
              <ErrorDetails issues={members.errors} />
            </Alert>
          </div>
        ) : null}
        {renderMemberTable(readyGroup.members.edges)}
      </>
    )
  }

  function renderMemberTable(edges: GroupNode['members']['edges']) {
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
        <DataTable.Body
          renderEmptyState={() => (
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
          )}
        >
          {edges.map((edge) => (
            <DataTable.Row key={edge.node.id} id={edge.node.id}>
              <DataTable.Cell>{renderMemberIdentity(edge)}</DataTable.Cell>
              <DataTable.Cell>
                {edge.enabled && !edge.revokedAt ? (
                  <Badge variant="secondary" className="text-success">
                    {t('groupMembersStatusActive')}
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    {t('groupMembersStatusRemoved')}
                  </Badge>
                )}
              </DataTable.Cell>
              <DataTable.Cell>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(edge.createdAt, locale, timeZone)}
                </span>
                {edge.revokedAt ? (
                  <span className="mt-0.5 block whitespace-nowrap text-xs text-muted-foreground">
                    {formatDateTime(edge.revokedAt, locale, timeZone)}
                  </span>
                ) : null}
              </DataTable.Cell>
              <DataTable.Cell>
                {edge.enabled && !edge.revokedAt ? (
                  scope.groupMembershipsWrite ? (
                    <RemoveMemberDialog
                      groupId={readyGroup.id}
                      userId={edge.node.id}
                      username={edge.node.username}
                      groupVersion={readyGroup.version}
                      onRemoved={() => {
                        setNotice({
                          kind: 'success',
                          title: t('groupMembersRemovedToast'),
                          description: t('groupMembersRemovedCommitted'),
                        })
                      }}
                      onReload={() => void members.refresh()}
                      reloadPending={members.refreshing}
                    />
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      {t('groupMembersNoWritePermission')}
                    </span>
                  )
                ) : (
                  <span className="text-xs text-muted-foreground">
                    {t('groupMembersRevokedAt', {
                      date: formatDateTime(edge.revokedAt, locale, timeZone),
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

  function renderMemberIdentity(edge: MemberEdge) {
    const user = edge.node
    return (
      <div className="min-w-52">
        <Link
          to="/users/$userId"
          params={{ userId: user.id }}
          className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          {user.username}
        </Link>
        {user.email ? (
          <p className="mt-0.5 break-all text-xs text-muted-foreground">
            {user.email}
          </p>
        ) : null}
        {edge.grantedBy ? (
          <p className="mt-1 break-all text-[11px] text-muted-foreground">
            {t('groupMembersGrantedByLabel')}: {edge.grantedBy.username}
          </p>
        ) : null}
      </div>
    )
  }
}
