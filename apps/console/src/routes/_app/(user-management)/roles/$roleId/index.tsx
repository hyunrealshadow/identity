import { createFileRoute } from '@tanstack/react-router'

import { RoleDetailPage } from '#/modules/user-management/roles/pages/role-detail-page'

function RoleDetailRouteComponent() {
  const { roleId } = Route.useParams()
  return <RoleDetailPage key={roleId} />
}

export const Route = createFileRoute('/_app/(user-management)/roles/$roleId/')({
  component: RoleDetailRouteComponent,
})
