import { createFileRoute } from '@tanstack/react-router'

import { RolePermissionsPage } from '#/modules/user-management/roles/pages/role-permissions-page'

function RolePermissionsRouteComponent() {
  const { roleId } = Route.useParams()
  return <RolePermissionsPage key={roleId} roleId={roleId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/roles/$roleId/permissions',
)({
  staticData: { breadcrumbs: [{ label: 'rolePermissionsTitle' }] },
  component: RolePermissionsRouteComponent,
})
