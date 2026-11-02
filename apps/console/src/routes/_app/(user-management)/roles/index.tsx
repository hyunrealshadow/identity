import { createFileRoute } from '@tanstack/react-router'

import { RolesListPage } from '#/modules/user-management/roles/pages/roles-list-page'
import {
  normalizeRolesSearch,
  type RolesSearch,
} from '#/modules/user-management/roles/lib/roles-search'

function RolesRouteComponent() {
  const search = Route.useSearch()
  return <RolesListPage search={search} />
}

export const Route = createFileRoute('/_app/(user-management)/roles/')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'rolesTitle', to: '/roles' },
    ],
  },
  validateSearch: (search: Record<string, unknown>): RolesSearch =>
    normalizeRolesSearch(search),
  component: RolesRouteComponent,
})
