import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/health/live')({
  server: {
    handlers: {
      GET: () =>
        new Response(JSON.stringify({ status: 'ok' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    },
  },
})