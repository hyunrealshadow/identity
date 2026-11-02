import { createFileRoute } from '@tanstack/react-router'

import { UserDetailPage } from '#/modules/user-management/users/pages/user-detail-page'

function UserDetailRouteComponent() {
  return <UserDetailPage />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/',
)({
  component: UserDetailRouteComponent,
})
