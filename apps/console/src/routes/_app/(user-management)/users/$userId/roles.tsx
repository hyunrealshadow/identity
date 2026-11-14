import { createFileRoute } from '@tanstack/react-router'

import { normalizeUserRolesSearch } from '#/modules/user-management/authorization/lib/user-authorization-search'
import { UserRolesPage } from '#/modules/user-management/authorization/pages/user-roles-page'

function UserRolesRouteComponent() {
  const { userId } = Route.useParams()
  const listSearch = Route.useSearch()
  return <UserRolesPage key={userId} userId={userId} listSearch={listSearch} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/roles',
)({
  staticData: { breadcrumbs: [{ label: 'userRolesTitle' }] },
  validateSearch: normalizeUserRolesSearch,
  component: UserRolesRouteComponent,
})
