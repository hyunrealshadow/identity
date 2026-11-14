import { createFileRoute } from '@tanstack/react-router'

import { normalizeUserPermissionsSearch } from '#/modules/user-management/authorization/lib/user-authorization-search'
import { UserEffectivePermissionsPage } from '#/modules/user-management/authorization/pages/user-effective-permissions-page'

function UserPermissionsRouteComponent() {
  const { userId } = Route.useParams()
  const listSearch = Route.useSearch()
  return <UserEffectivePermissionsPage key={userId} userId={userId} listSearch={listSearch} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/permissions',
)({
  staticData: { breadcrumbs: [{ label: 'userPermissionsTitle' }] },
  validateSearch: normalizeUserPermissionsSearch,
  component: UserPermissionsRouteComponent,
})
