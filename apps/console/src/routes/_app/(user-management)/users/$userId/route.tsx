import { Outlet, createFileRoute, useLocation } from '@tanstack/react-router'

import { UserDetailLayout as SharedUserDetailLayout } from '#/modules/user-management/users/components/user-detail-layout'

export const Route = createFileRoute('/_app/(user-management)/users/$userId')({
  staticData: {
    breadcrumbs: [
      { label: 'navUserManagement', link: false },
      { label: 'usersTitle', to: '/users' },
      { label: 'usersDetailTitle' },
    ],
  },
  component: UserDetailLayout,
})

function UserDetailLayout() {
  const { userId } = Route.useParams()
  const pathname = useLocation({ select: (location) => location.pathname })
  if (pathname.endsWith('/edit')) return <Outlet />
  const tab = pathname.endsWith('/groups')
    ? '/users/$userId/groups'
    : pathname.endsWith('/roles')
      ? '/users/$userId/roles'
      : pathname.endsWith('/permissions')
        ? '/users/$userId/permissions'
        : '/users/$userId'
  return (
    <SharedUserDetailLayout key={userId} userId={userId} current={tab}>
      <Outlet />
    </SharedUserDetailLayout>
  )
}
