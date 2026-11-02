import { createFileRoute } from '@tanstack/react-router'

import { RoleDetailShell } from '#/modules/user-management/roles/components/role-detail-shell'

export const Route = createFileRoute('/_app/(user-management)/roles/$roleId')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'rolesTitle', to: '/roles' },
      { label: 'roleDetailTitle' },
    ],
  },
  component: RoleDetailLayout,
})

function RoleDetailLayout() {
  const { roleId } = Route.useParams()
  return <RoleDetailShell roleId={roleId} />
}
