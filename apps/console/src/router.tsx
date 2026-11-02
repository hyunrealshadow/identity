import { createRouter } from '@tanstack/react-router'

import type { RuntimeConfig } from '#/lib/config'
import { routeTree } from './routeTree.gen'

export interface RouterContext {
  config: RuntimeConfig
}

export function createAppRouter(config: RuntimeConfig) {
  return createRouter({
    routeTree,
    context: { config },
    defaultPreload: 'intent',
    scrollRestoration: true,
  })
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>
  }
}
