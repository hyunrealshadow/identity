import {
  HeadContent,
  Scripts,
  createRootRoute,
  redirect,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import appCss from '../styles.css?url'
import { identityJson } from '#/lib/identity.server'
import type { InstallationStatusResponse } from '#/lib/identity-types'

const loadInstallationStatus = createServerFn({ method: 'GET' }).handler(
  () => identityJson<InstallationStatusResponse>('/installation/status'),
)

export const Route = createRootRoute({
  beforeLoad: async ({ location }) => {
    const { installed } = await loadInstallationStatus()
    const isInstallRoute = location.pathname === '/install'

    if (!installed && !isInstallRoute) {
      throw redirect({ to: '/install' })
    }
    if (installed && isInstallRoute) {
      throw redirect({ to: '/' })
    }
  },
  head: () => ({
    meta: [
      {
        charSet: 'utf-8',
      },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1',
      },
      {
        title: 'Identity',
      },
    ],
    links: [
      {
        rel: 'stylesheet',
        href: appCss,
      },
    ],
  }),
  shellComponent: RootDocument,
})

function RootDocument({ children }: { children: React.ReactNode }) {
  const locale = useRouterState({
    select: (state) => {
      for (const match of [...state.matches].reverse()) {
        const data = match.loaderData as { locale?: string } | undefined
        if (data?.locale) return data.locale
      }
      return 'en-US'
    },
  })

  return (
    <html lang={locale}>
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  )
}
