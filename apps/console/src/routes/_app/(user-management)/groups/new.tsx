import { createFileRoute } from '@tanstack/react-router'

import { GroupCreatePage } from '#/modules/user-management/groups/pages/group-create-page'

export const Route = createFileRoute('/_app/(user-management)/groups/new')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'groupsTitle', to: '/groups' },
      { label: 'groupsNewTitle' },
    ],
  },
  component: GroupCreatePage,
})
