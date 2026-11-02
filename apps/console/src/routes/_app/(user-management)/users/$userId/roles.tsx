import { createFileRoute } from '@tanstack/react-router'

import { UserRolesPage } from '#/modules/user-management/authorization/pages/user-roles-page'

function UserRolesRouteComponent() {
  const { userId } = Route.useParams()
  return <UserRolesPage key={userId} userId={userId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/roles',
)({
  staticData: { breadcrumbs: [{ label: 'userRolesTitle' }] },
  component: UserRolesRouteComponent,
})
