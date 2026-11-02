import { createFileRoute } from '@tanstack/react-router'

import { UserCreatePage } from '#/modules/user-management/users/pages/user-create-page'

export const Route = createFileRoute('/_app/(user-management)/users/new')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'usersTitle', to: '/users' },
      { label: 'usersNewTitle' },
    ],
  },
  component: UserCreatePage,
})
