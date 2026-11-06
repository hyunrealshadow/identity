import { DataTable } from '@identity/ui/data-table'
import { Button } from '@heroui/react'
import { Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsolePermissionRolesDocument,
  type ConsolePermissionRolesQuery,
  type ConsolePermissionRolesQueryVariables,
} from '#/generated/graphql'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import {
  RoleBuiltInChip,
  RoleStatusChip,
} from '#/modules/user-management/roles/components/role-status'

export function PermissionRoleReferences({
  permissionId,
}: {
  permissionId: string
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const [after, setAfter] = useState<string>()
  const [before, setBefore] = useState<string>()
  const enabled = scope.permissionRead && scope.rolesRead
  const variables = useMemo<ConsolePermissionRolesQueryVariables | null>(
    () =>
      enabled ? { id: permissionId, ...cursorPage(5, after, before) } : null,
    [enabled, permissionId, after, before],
  )
  const query = useConsoleQuery<
    ConsolePermissionRolesQuery,
    ConsolePermissionRolesQueryVariables
  >(
    ConsolePermissionRolesDocument,
    variables,
    enabled,
    'missing_permission_roles',
    { keepPreviousData: sameVariable('id') },
  )
  const connection = query.data?.permission?.roles

  return (
    <section className="space-y-4 border-t border-separator pt-5">
      <header className="py-2">
        <h2>{t('permissionsRolesTitle')}</h2>
        <p>{t('permissionsRolesDescription')}</p>
      </header>
      <div className="space-y-4">
        {!enabled ? (
          <p className="text-sm text-muted">
            {t('permissionsRolesReadRequired')}
          </p>
        ) : query.stepUp ? (
          <StepUpPanel stepUp={query.stepUp} hideDetails />
        ) : query.status === 'error' ? (
          <>
            <AsyncState
              kind="error"
              title={t('errorTitle')}
              onRetry={() => void query.refresh()}
            />
            <RequestCorrelation
              requestId={query.requestId}
              traceId={query.traceId}
            />
            <ErrorDetails issues={query.errors} />
          </>
        ) : !connection ? (
          <AsyncState kind="loading" title={t('loading')} />
        ) : connection.edges.length === 0 ? (
          <AsyncState
            kind="empty"
            compact
            title={t('permissionsRolesEmptyTitle')}
          />
        ) : (
          <>
            {query.partial ? <ErrorDetails issues={query.errors} /> : null}
            <DataTable
              label={t('permissionsRolesTitle')}
              minWidth={420}
              columns={[
                {
                  id: 'rolesFieldName',
                  label: t('rolesFieldName'),
                  primary: true,
                },
                {
                  id: 'rolesColumnStatus',
                  label: t('rolesColumnStatus'),
                  primary: false,
                },
              ]}
            >
              <DataTable.Body>
                {connection.edges.map(({ node }) => (
                  <DataTable.Row key={node.id} id={node.id}>
                    <DataTable.Cell>
                      <Link
                        to="/roles/$roleId"
                        params={{ roleId: node.id }}
                        className="font-medium hover:underline"
                      >
                        {(resolveLocalizedText(node.names, locale) ?? node.name) ??
                          node.name ??
                          node.id}
                      </Link>
                      <RoleBuiltInChip builtIn={node.builtIn} />
                    </DataTable.Cell>
                    <DataTable.Cell>
                      <RoleStatusChip enabled={node.enabled} />
                    </DataTable.Cell>
                  </DataTable.Row>
                ))}
              </DataTable.Body>
            </DataTable>
            <nav
              className="flex justify-end gap-2"
              aria-label={t('rolesPaginationLabel')}
            >
              <Button
                size="sm"
                variant="secondary"
                isDisabled={
                  !connection.pageInfo.hasPreviousPage || query.refreshing
                }
                onPress={() => {
                  setBefore(connection.pageInfo.startCursor ?? undefined)
                  setAfter(undefined)
                }}
              >
                {t('previousPage')}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                isDisabled={
                  !connection.pageInfo.hasNextPage || query.refreshing
                }
                onPress={() => {
                  setAfter(connection.pageInfo.endCursor ?? undefined)
                  setBefore(undefined)
                }}
              >
                {t('nextPage')}
              </Button>
            </nav>
          </>
        )}
      </div>
    </section>
  )
}
