import { createFileRoute } from '@tanstack/react-router'

import { normalizeUserGroupsSearch } from '#/modules/user-management/users/lib/user-groups-search'
import { UserGroupsPage } from '#/modules/user-management/users/pages/user-groups-page'

function UserGroupsRouteComponent() {
  const { userId } = Route.useParams()
  const search = Route.useSearch()
  return <UserGroupsPage key={userId} userId={userId} search={search} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/users/$userId/groups',
)({
  staticData: { breadcrumbs: [{ label: 'userGroupsTitle' }] },
  validateSearch: normalizeUserGroupsSearch,
  component: UserGroupsRouteComponent,
})
