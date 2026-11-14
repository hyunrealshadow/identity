import { createFileRoute } from '@tanstack/react-router'

import { normalizeRoleGroupsSearch } from '#/modules/user-management/roles/lib/role-groups-search'
import { RoleGroupsPage } from '#/modules/user-management/roles/pages/role-groups-page'

function RoleGroupsRouteComponent() {
  const { roleId } = Route.useParams()
  const search = Route.useSearch()
  return <RoleGroupsPage key={roleId} roleId={roleId} search={search} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/roles/$roleId/groups',
)({
  staticData: { breadcrumbs: [{ label: 'roleGroupsTitle' }] },
  validateSearch: normalizeRoleGroupsSearch,
  component: RoleGroupsRouteComponent,
})
