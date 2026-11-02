import { createFileRoute } from '@tanstack/react-router'
import { PermissionDetailPage } from '#/modules/client-management/resources/permissions/pages/permission-detail-page'
export const Route = createFileRoute(
  '/_app/(client-management)/resources/$resourceId/permissions/$permissionId',
)({
  staticData: {
    breadcrumbs: [
      { label: 'permissionsTitle', to: '/resources/$resourceId/permissions' },
      { label: 'permissionsDetailTitle' },
    ],
  },
  component: () => (
    <PermissionDetailPage
      key={Route.useParams().permissionId}
      {...Route.useParams()}
    />
  ),
})
