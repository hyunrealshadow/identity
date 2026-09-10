import { createMiddleware, createStart } from '@tanstack/react-start'

import { forwardedProtoIsHttps } from '#/lib/upstream-https'

const healthRoutes = new Set(['/health/live', '/health/ready'])

const requireUpstreamHttps = createMiddleware().server(
  async ({ next, pathname, request }) => {
    if (
      process.env.IDENTITY_REQUIRE_UPSTREAM_HTTPS !== 'true' ||
      healthRoutes.has(pathname)
    ) {
      return next()
    }

    if (!forwardedProtoIsHttps(request.headers)) {
      return new Response('HTTPS forwarding metadata is required', {
        status: 400,
      })
    }

    return next()
  },
)

/**
 * One server span per inbound request. Browser traffic is untrusted, so a
 * valid `traceparent` becomes a span link instead of the local parent. The
 * observability module is imported dynamically because this file is shared
 * with the client build; the `.server()` callback itself is server-only.
 */
const traceRequests = createMiddleware().server(
  async ({ next, pathname, request }) => {
    // Successful probes stay out of traces; only their metrics and state
    // changes are kept.
    if (healthRoutes.has(pathname)) {
      return next()
    }
    const { initObservability, runWithServerSpan } = await import(
      '#/lib/observability.server'
    )
    initObservability()
    return runWithServerSpan(
      'http.server',
      {
        'http.request.method': request.method,
        'url.path': pathname,
      },
      request.headers.get('traceparent'),
      async () => next(),
    )
  },
)

export const startInstance = createStart(() => ({
  requestMiddleware: [requireUpstreamHttps, traceRequests],
}))
