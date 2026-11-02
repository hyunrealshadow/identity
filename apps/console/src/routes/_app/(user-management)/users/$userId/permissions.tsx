import { createFileRoute } from '@tanstack/react-router'

import { UserEffectivePermissionsPage } from '#/modules/user-management/authorization/pages/user-effective-permissions-page'

function UserPermissionsRouteComponent() {
  const { userId } = Route.useParams()
  return <UserEffectivePermissionsPage key={userId} userId={userId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/permissions',
)({
  staticData: { breadcrumbs: [{ label: 'userPermissionsTitle' }] },
  component: UserPermissionsRouteComponent,
})
