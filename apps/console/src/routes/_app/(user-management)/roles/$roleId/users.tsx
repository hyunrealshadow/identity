import { createFileRoute } from '@tanstack/react-router'

import { normalizeRoleUsersSearch } from '#/modules/user-management/roles/lib/role-users-search'
import { RoleUsersPage } from '#/modules/user-management/roles/pages/role-users-page'

function RoleUsersRouteComponent() {
  const { roleId } = Route.useParams()
  const listSearch = Route.useSearch()
  return <RoleUsersPage key={roleId} roleId={roleId} listSearch={listSearch} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/roles/$roleId/users',
)({
  staticData: { breadcrumbs: [{ label: 'roleUsersTitle' }] },
  validateSearch: normalizeRoleUsersSearch,
  component: RoleUsersRouteComponent,
})
