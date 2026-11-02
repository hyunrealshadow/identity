import { createFileRoute } from '@tanstack/react-router'
import { PermissionsListPage } from '#/modules/client-management/resources/permissions/pages/permissions-list-page'
import { normalizePermissionsSearch } from '#/modules/client-management/resources/permissions/lib/permissions-search'
export const Route = createFileRoute(
  '/_app/(client-management)/resources/$resourceId/permissions/',
)({
  staticData: { breadcrumbs: [{ label: 'permissionsTitle' }] },
  validateSearch: (search: Record<string, unknown>) =>
    normalizePermissionsSearch({ ...search, resourceId: undefined }),
  component: () => (
    <PermissionsListPage
      resourceId={Route.useParams().resourceId}
      search={Route.useSearch()}
    />
  ),
})
