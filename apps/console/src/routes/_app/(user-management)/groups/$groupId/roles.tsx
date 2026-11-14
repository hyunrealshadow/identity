import { createFileRoute } from '@tanstack/react-router'

import { normalizeGroupRolesSearch } from '#/modules/user-management/groups/lib/group-relations-search'
import { GroupRolesPage } from '#/modules/user-management/groups/pages/group-roles-page'

function GroupRolesRouteComponent() {
  const { groupId } = Route.useParams()
  const listSearch = Route.useSearch()
  return <GroupRolesPage key={groupId} groupId={groupId} listSearch={listSearch} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/groups/$groupId/roles',
)({
  staticData: { breadcrumbs: [{ label: 'groupRolesTitle' }] },
  validateSearch: normalizeGroupRolesSearch,
  component: GroupRolesRouteComponent,
})
