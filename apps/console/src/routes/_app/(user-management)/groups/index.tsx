import { createFileRoute } from '@tanstack/react-router'

import { GroupsListPage } from '#/modules/user-management/groups/pages/groups-list-page'
import {
  normalizeGroupsSearch,
  type GroupsSearch,
} from '#/modules/user-management/groups/lib/groups-search'

function GroupsRouteComponent() {
  const search = Route.useSearch()
  return <GroupsListPage search={search} />
}

export const Route = createFileRoute('/_app/(user-management)/groups/')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'groupsTitle', to: '/groups' },
    ],
  },
  validateSearch: (search: Record<string, unknown>): GroupsSearch =>
    normalizeGroupsSearch(search),
  component: GroupsRouteComponent,
})
