import { createFileRoute } from '@tanstack/react-router'

import { UserGroupsPage } from '#/modules/user-management/users/pages/user-groups-page'

function UserGroupsRouteComponent() {
  const { userId } = Route.useParams()
  return <UserGroupsPage key={userId} userId={userId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/groups',
)({
  staticData: { breadcrumbs: [{ label: 'userGroupsTitle' }] },
  component: UserGroupsRouteComponent,
})
