import { createFileRoute } from '@tanstack/react-router'

import { GroupRolesPage } from '#/modules/user-management/groups/pages/group-roles-page'

function GroupRolesRouteComponent() {
  const { groupId } = Route.useParams()
  return <GroupRolesPage key={groupId} groupId={groupId} />
}

export const Route = createFileRoute(
  '/_app/(user-management)/groups/$groupId/roles',
)({
  staticData: { breadcrumbs: [{ label: 'groupRolesTitle' }] },
  component: GroupRolesRouteComponent,
})
