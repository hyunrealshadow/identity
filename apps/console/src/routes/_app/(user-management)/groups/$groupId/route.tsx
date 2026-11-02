import { createFileRoute } from '@tanstack/react-router'

import { GroupDetailShell } from '#/modules/user-management/groups/components/group-detail-shell'

export const Route = createFileRoute('/_app/(user-management)/groups/$groupId')(
  {
    staticData: {
      breadcrumbs: [
        { label: 'navUserManagement', link: false },
        { label: 'groupsTitle', to: '/groups' },
        { label: 'groupDetailTitle' },
      ],
    },
    component: GroupDetailLayout,
  },
)

function GroupDetailLayout() {
  const { groupId } = Route.useParams()
  return <GroupDetailShell groupId={groupId} />
}
