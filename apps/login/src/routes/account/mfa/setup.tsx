import { createFileRoute } from '@tanstack/react-router'

import {
  handleAccountMfaSetupGet,
  handleAccountMfaSetupPost,
} from '#/modules/account/lib/account-mfa-setup.server'

export const Route = createFileRoute('/account/mfa/setup')({
  server: {
    handlers: {
      GET: () => handleAccountMfaSetupGet(),
      POST: ({ request }) => handleAccountMfaSetupPost(request),
    },
  },
})
