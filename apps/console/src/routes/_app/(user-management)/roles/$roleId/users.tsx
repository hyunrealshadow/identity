import { createFileRoute } from '@tanstack/react-router'

import { RoleUsersPage } from '#/modules/user-management/roles/pages/role-users-page'

function RoleUsersRouteComponent() {
  const { roleId } = Route.useParams()
  return <RoleUsersPage key={roleId} roleId={roleId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/roles/$roleId/users',
)({
  staticData: { breadcrumbs: [{ label: 'roleUsersTitle' }] },
  component: RoleUsersRouteComponent,
})
