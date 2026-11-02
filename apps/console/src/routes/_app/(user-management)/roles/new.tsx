import { createFileRoute } from '@tanstack/react-router'

import { RoleCreatePage } from '#/modules/user-management/roles/pages/role-create-page'

export const Route = createFileRoute('/_app/(user-management)/roles/new')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'rolesTitle', to: '/roles' },
      { label: 'rolesNewTitle' },
    ],
  },
  component: RoleCreatePage,
})
