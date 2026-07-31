import { createFileRoute } from '@tanstack/react-router'

import { startAuthorization } from '#/lib/oauth.server'

export const Route = createFileRoute('/oauth/start')({
  server: {
    handlers: {
      GET: () => startAuthorization(),
    },
  },
})
