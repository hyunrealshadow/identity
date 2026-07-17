import { createFileRoute } from '@tanstack/react-router'

import { identityResponse } from '#/lib/identity.server'

export const Route = createFileRoute('/oauth2/continue')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url)
        return identityResponse(`${url.pathname}${url.search}`)
      },
    },
  },
})
