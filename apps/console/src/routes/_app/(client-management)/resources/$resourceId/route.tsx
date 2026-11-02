import { createFileRoute } from '@tanstack/react-router'
import { ResourceDetailShell } from '#/modules/client-management/resources/components/resource-detail-shell'
export const Route = createFileRoute(
  '/_app/(client-management)/resources/$resourceId',
)({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'resourcesTitle', to: '/resources' },
      { label: 'resourcesDetailTitle' },
    ],
  },
  component: () => (
    <ResourceDetailShell resourceId={Route.useParams().resourceId} />
  ),
})
