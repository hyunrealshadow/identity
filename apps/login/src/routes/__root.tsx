import {
  HeadContent,
  Scripts,
  createRootRoute,
  redirect,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import appCss from '../styles.css?url'
import { cachedInstallationStatus } from '#/lib/installation-status.server'

const loadInstallationStatus = createServerFn({ method: 'GET' }).handler(
  () => cachedInstallationStatus(),
)

export const Route = createRootRoute({
  staleTime: Infinity,
  loader: async ({ location }) => {
    const { installed } = await loadInstallationStatus()
    const isInstallRoute = location.pathname === '/install'

    if (!installed && !isInstallRoute) {
      throw redirect({ to: '/install' })
    }
    if (installed && isInstallRoute) {
      throw redirect({ to: '/' })
    }
    return { installed }
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
    scripts: [
      {
        children: `document.documentElement.classList.replace('no-js','js')`,
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
    <html lang={locale} className="no-js" suppressHydrationWarning>
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
