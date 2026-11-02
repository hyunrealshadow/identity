import { createFileRoute } from '@tanstack/react-router'
import { ResourcesListPage } from '#/modules/client-management/resources/pages/resources-list-page'
import { normalizeResourcesSearch } from '#/modules/client-management/resources/lib/resources-search'
export const Route = createFileRoute('/_app/(client-management)/resources/')({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'resourcesTitle', to: '/resources' },
    ],
  },
  validateSearch: normalizeResourcesSearch,
  component: () => <ResourcesListPage search={Route.useSearch()} />,
})
