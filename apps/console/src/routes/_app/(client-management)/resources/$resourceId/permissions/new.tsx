import { createFileRoute } from '@tanstack/react-router'
import { PermissionCreatePage } from '#/modules/client-management/resources/permissions/pages/permission-create-page'
export const Route = createFileRoute(
  '/_app/(client-management)/resources/$resourceId/permissions/new',
)({
  staticData: {
    breadcrumbs: [
      { label: 'permissionsTitle', to: '/resources/$resourceId/permissions' },
      { label: 'permissionsNewTitle' },
    ],
  },
  component: () => (
    <PermissionCreatePage
      key={Route.useParams().resourceId}
      resourceId={Route.useParams().resourceId}
    />
  ),
})
