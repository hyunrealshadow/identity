import { createFileRoute } from '@tanstack/react-router'

import { finishAuthorization } from '#/lib/oauth.server'

export const Route = createFileRoute('/oauth/callback')({
  server: {
    handlers: {
      GET: ({ request }) => finishAuthorization(request),
    },
  },
})
