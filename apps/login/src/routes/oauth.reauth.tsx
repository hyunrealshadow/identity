import { createFileRoute } from '@tanstack/react-router'

import { startReauthorization } from '#/lib/oauth.server'

export const Route = createFileRoute('/oauth/reauth')({
  server: {
    handlers: {
      GET: ({ request }) => {
        const returnTo = new URL(request.url).searchParams.get('return_to')
        const requestedPurpose = new URL(request.url).searchParams.get('purpose')
        const purpose =
          requestedPurpose === 'mfa' || requestedPurpose === 'account'
            ? requestedPurpose
            : 'password'
        return startReauthorization(returnTo ?? undefined, purpose)
      },
    },
  },
})
