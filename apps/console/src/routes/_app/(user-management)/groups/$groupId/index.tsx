import { createFileRoute } from '@tanstack/react-router'

import { GroupDetailPage } from '#/modules/user-management/groups/pages/group-detail-page'

function GroupDetailRouteComponent() {
  const { groupId } = Route.useParams()
  return <GroupDetailPage key={groupId} groupId={groupId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/groups/$groupId/',
)({
  component: GroupDetailRouteComponent,
})
