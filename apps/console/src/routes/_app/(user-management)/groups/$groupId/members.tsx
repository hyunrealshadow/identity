import { createFileRoute } from '@tanstack/react-router'

import { normalizeGroupMembersSearch } from '#/modules/user-management/groups/lib/group-relations-search'
import { GroupMembersPage } from '#/modules/user-management/groups/pages/group-members-page'

function GroupMembersRouteComponent() {
  const { groupId } = Route.useParams()
  const listSearch = Route.useSearch()
  return <GroupMembersPage key={groupId} groupId={groupId} listSearch={listSearch} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/groups/$groupId/members',
)({
  staticData: { breadcrumbs: [{ label: 'groupMembersTitle' }] },
  validateSearch: normalizeGroupMembersSearch,
  component: GroupMembersRouteComponent,
})
