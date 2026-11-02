import { createFileRoute } from '@tanstack/react-router'

import { GroupMembersPage } from '#/modules/user-management/groups/pages/group-members-page'

function GroupMembersRouteComponent() {
  const { groupId } = Route.useParams()
  return <GroupMembersPage key={groupId} groupId={groupId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/groups/$groupId/members',
)({
  staticData: { breadcrumbs: [{ label: 'groupMembersTitle' }] },
  component: GroupMembersRouteComponent,
})
