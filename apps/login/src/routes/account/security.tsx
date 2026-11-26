import { createFileRoute } from '@tanstack/react-router'

import {
  SecurityPageView,
  type SecuritySearch,
} from '#/modules/account/pages/security-page'

export const Route = createFileRoute('/account/security')({
  validateSearch: (search): SecuritySearch => ({
    setup: search.setup === 'mfa' ? 'mfa' : undefined,
    step: search.step === 'verify' ? 'verify' : undefined,
    confirm:
      search.confirm === 'disable-mfa' ||
      search.confirm === 'change-password' ||
      search.confirm === 'recovery-codes' ||
      search.confirm === 'passkeys'
        ? search.confirm
        : undefined,
  }),
  component: SecurityRoute,
})

function SecurityRoute() {
  const search = Route.useSearch()
  return <SecurityPageView search={search} />
}
