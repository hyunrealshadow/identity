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

export const startInstance = createStart(() => ({
  requestMiddleware: [requireUpstreamHttps],
}))
