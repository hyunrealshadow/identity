import { createFileRoute } from '@tanstack/react-router'

import { renderMetrics } from '#/lib/observability.server'

/**
 * Independent scrape endpoint for Login observability pipeline failures. It is
 * deliberately separate from readiness so a saturated or broken collector is
 * still observable. Deployment may disable it by omitting the env flag.
 */
export const Route = createFileRoute('/health/metrics')({
  server: {
    handlers: {
      GET: () => {
        if (process.env.IDENTITY_LOGIN_METRICS_ENABLE !== 'true') {
          return new Response('not found', { status: 404 })
        }
        return new Response(renderMetrics(), {
          status: 200,
          headers: { 'content-type': 'text/plain; version=0.0.4' },
        })
      },
    },
  },
})
