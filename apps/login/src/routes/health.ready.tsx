import { createFileRoute } from '@tanstack/react-router'

import { applicationReadiness } from '#/lib/readiness.server'

export const Route = createFileRoute('/health/ready')({
  server: {
    handlers: {
      GET: async () => {
        const readiness = await applicationReadiness()
        return new Response(
          JSON.stringify({
            status: readiness.ready ? 'ready' : 'unready',
            reason: readiness.reason,
          }),
          {
            status: readiness.ready ? 200 : 503,
            headers: { 'content-type': 'application/json' },
          },
        )
      },
    },
  },
})
