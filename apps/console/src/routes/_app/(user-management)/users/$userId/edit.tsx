import { createFileRoute } from '@tanstack/react-router'

import { UserEditPage } from '#/modules/user-management/users/pages/user-edit-page'

function UserEditRouteComponent() {
  const { userId } = Route.useParams()
  return <UserEditPage key={userId} userId={userId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/edit',
)({
  staticData: { breadcrumbs: [{ label: 'usersEditTitle' }] },
  component: UserEditRouteComponent,
})
