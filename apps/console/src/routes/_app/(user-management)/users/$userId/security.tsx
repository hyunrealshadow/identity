import { createFileRoute } from '@tanstack/react-router'

import { UserSecurityPage } from '#/modules/user-management/users/pages/user-security-page'

export const Route = createFileRoute('/_app/(user-management)/users/$userId/security')({
  staticData: { breadcrumbs: [{ label: 'userDetailsTabSecurity' }] },
  component: UserSecurityPage,
})
