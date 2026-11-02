import { createFileRoute } from '@tanstack/react-router'

import { UsersListPage } from '#/modules/user-management/users/pages/users-list-page'
import {
  validateUsersSearch,
  type UsersSearch,
} from '#/modules/user-management/users/lib/users-search'

function UsersRouteComponent() {
  const search = Route.useSearch()
  return <UsersListPage search={search} />
}

export const Route = createFileRoute('/_app/(user-management)/users/')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'usersTitle', to: '/users' },
    ],
  },
  validateSearch: (search: Record<string, unknown>): UsersSearch =>
    validateUsersSearch(search),
  component: UsersRouteComponent,
})
