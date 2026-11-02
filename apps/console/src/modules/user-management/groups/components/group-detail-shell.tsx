import { GroupDetailContext } from './group-detail-context'
import { Button, Skeleton } from '@heroui/react'
import { Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { useMemo } from 'react'
import {
  ConsoleGroupDocument,
  type ConsoleGroupQuery,
  type ConsoleGroupQueryVariables,
} from '#/gql/graphql'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { GroupDetailTabs } from '#/modules/user-management/components/detail-tabs'
import {
  GroupKindChip,
  GroupStatusChip,
} from '#/modules/user-management/groups/components/group-status'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

type TabPath =
  '/groups/$groupId' | '/groups/$groupId/members' | '/groups/$groupId/roles'

export function GroupDetailShell({ groupId }: { groupId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })
  const current = ('/groups/$groupId' +
    (['members', 'roles'].find((tab) => pathname.endsWith('/' + tab))
      ? '/' + pathname.split('/').at(-1)
      : '')) as TabPath
  const variables = useMemo(
    () => (scope.groupsRead ? { id: groupId } : null),
    [groupId, scope.groupsRead],
  )
  const query = useConsoleQuery<ConsoleGroupQuery, ConsoleGroupQueryVariables>(
    ConsoleGroupDocument,
    variables,
    'ConsoleGroup',
    Boolean(variables),
    'missing_group',
  )
  const record = query.data?.group
  const name = record
    ? (resolveLocalizedText(record.names, locale) ??
      record.name ??
      t('groupDetailTitle'))
    : undefined
  const description = record
    ? (resolveLocalizedText(record.descriptions, locale) ?? record.description)
    : undefined
  useBreadcrumbLabel(`/groups/${groupId}`, name)
  return (
    <>
      <header className="mb-6 space-y-5">
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2"
          onPress={() => void navigate({ to: '/groups' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToGroups')}
        </Button>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">
              {name ??
                (query.status === 'loading' || query.status === 'idle' ? (
                  <Skeleton className="h-8 w-52 rounded-field" />
                ) : (
                  t('groupDetailTitle')
                ))}
            </h1>
            {record ? (
              <>
                <GroupKindChip builtIn={record.builtIn} />
                <GroupStatusChip enabled={record.enabled} />
              </>
            ) : null}
          </div>
          {description ? (
            <p className="max-w-3xl text-sm text-muted">{description}</p>
          ) : null}
        </div>
      </header>
      <GroupDetailTabs groupId={groupId} current={current} />
      <GroupDetailContext.Provider value={query}>
        <Outlet />
      </GroupDetailContext.Provider>
    </>
  )
}
