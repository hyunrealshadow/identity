import { RoleDetailContext } from './role-detail-context'
import { Button, Skeleton } from '@heroui/react'
import { Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { useMemo } from 'react'
import {
  ConsoleRoleDocument,
  type ConsoleRoleQuery,
  type ConsoleRoleQueryVariables,
} from '#/generated/graphql'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { RoleDetailTabs } from '#/modules/user-management/components/detail-tabs'
import {
  RoleBuiltInChip,
  RoleStatusChip,
} from '#/modules/user-management/roles/components/role-status'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

type TabPath =
  | '/roles/$roleId'
  | '/roles/$roleId/permissions'
  | '/roles/$roleId/users'
  | '/roles/$roleId/groups'

export function RoleDetailShell({ roleId }: { roleId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })
  const current = ('/roles/$roleId' +
    (['permissions', 'users', 'groups'].find((tab) =>
      pathname.endsWith('/' + tab),
    )
      ? '/' + pathname.split('/').at(-1)
      : '')) as TabPath
  const variables = useMemo(
    () => (scope.rolesRead ? { id: roleId } : null),
    [roleId, scope.rolesRead],
  )
  const query = useConsoleQuery<ConsoleRoleQuery, ConsoleRoleQueryVariables>(
    ConsoleRoleDocument,
    variables,
    Boolean(variables),
    'missing_role',
  )
  const record = query.data?.role
  const name = record
    ? (resolveLocalizedText(record.names, locale) ?? record.name)
    : undefined
  const description = record
    ? (resolveLocalizedText(record.descriptions, locale) ?? record.description)
    : undefined
  useBreadcrumbLabel(`/roles/${roleId}`, name)
  return (
    <>
      <header className="mb-6 space-y-5">
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2"
          onPress={() => void navigate({ to: '/roles' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToRoles')}
        </Button>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">
              {name ??
                (query.status === 'loading' || query.status === 'idle' ? (
                  <Skeleton className="h-8 w-52 rounded-field" />
                ) : (
                  t('roleDetailTitle')
                ))}
            </h1>
            {record ? (
              <>
                <RoleBuiltInChip builtIn={record.builtIn} />
                <RoleStatusChip enabled={record.enabled} />
              </>
            ) : null}
          </div>
          {description ? (
            <p className="max-w-3xl text-sm text-muted">{description}</p>
          ) : null}
        </div>
      </header>
      <RoleDetailTabs roleId={roleId} current={current} />
      <RoleDetailContext.Provider value={query}>
        <Outlet />
      </RoleDetailContext.Provider>
    </>
  )
}
