import { createFileRoute } from '@tanstack/react-router'

import { RoleGroupsPage } from '#/modules/user-management/roles/pages/role-groups-page'

function RoleGroupsRouteComponent() {
  const { roleId } = Route.useParams()
  return <RoleGroupsPage key={roleId} roleId={roleId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/roles/$roleId/groups',
)({
  staticData: { breadcrumbs: [{ label: 'roleGroupsTitle' }] },
  component: RoleGroupsRouteComponent,
})
