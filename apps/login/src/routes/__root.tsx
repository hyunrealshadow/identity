import {
  HeadContent,
  Scripts,
  createRootRoute,
  redirect,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import appCss from '../styles.css?url'
import { anonymousThemePreference } from '#/lib/appearance.server'
import { cachedInstallationStatus } from '#/lib/installation-status.server'

const initializeAppearance = `(()=>{const d=document.documentElement,p=d.dataset.themePreference,s='identity-theme';let v=p;if(!v){try{v=localStorage.getItem(s)}catch{}}const t=v==='dark'||(v!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';d.dataset.theme=t;d.classList.remove('no-js','light','dark');d.classList.add('js',t)})()`

const loadRootState = createServerFn({ method: 'GET' }).handler(async () => ({
  ...(await cachedInstallationStatus()),
  theme: anonymousThemePreference(),
}))

export const Route = createRootRoute({
  staleTime: Infinity,
  loader: async ({ location }) => {
    const { installed, theme } = await loadRootState()
    const isInstallRoute = location.pathname === '/install'

    if (!installed && !isInstallRoute) {
      throw redirect({ to: '/install' })
    }
    if (installed && isInstallRoute) {
      throw redirect({ to: '/' })
    }
    return { installed, theme }
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
        children: initializeAppearance,
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
  const themePreference = useRouterState({
    select: (state) => {
      for (const match of [...state.matches].reverse()) {
        const data = match.loaderData as { theme?: string } | undefined
        if (data?.theme === 'light' || data?.theme === 'dark' || data?.theme === 'system') {
          return data.theme
        }
      }
      return undefined
    },
  })
  const serverTheme = themePreference === 'light' || themePreference === 'dark'
    ? themePreference
    : undefined

  return (
    <html
      lang={locale}
      className={`no-js${serverTheme ? ` ${serverTheme}` : ''}`}
      data-theme={serverTheme}
      data-theme-preference={themePreference}
      suppressHydrationWarning
    >
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
