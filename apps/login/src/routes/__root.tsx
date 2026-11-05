import { resolveLocale, translate } from '#/lib/i18n'
import {
  HeadContent,
  Scripts,
  createRootRouteWithContext,
  redirect,
  useRouterState,
  type ErrorComponentProps,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import appCss from '../styles.css?url'
import { anonymousThemePreference } from '#/lib/appearance.server'
import { cachedInstallationStatus } from '#/lib/installation-status.server'
import { requestLocale } from '#/lib/i18n.server'

const initializeAppearance = `(()=>{const d=document.documentElement,p=d.dataset.themePreference,s='identity-theme';let v=p;if(!v){try{v=localStorage.getItem(s)}catch{}}const t=v==='dark'||(v!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';d.dataset.theme=t;d.classList.remove('no-js','light','dark');d.classList.add('js',t)})()`

const loadRootState = createServerFn({ method: 'GET' }).handler(async () => ({
  ...(await cachedInstallationStatus()),
  theme: anonymousThemePreference(),
}))

// Resolve language before the installation-status request can fail, so the
// root boundary remains localized even when Identity is unavailable.
const loadRootLocale = createServerFn({ method: 'GET' })
  .validator((data: { uiLocales?: string }) => data)
  .handler(({ data }) => requestLocale(data.uiLocales?.split(' ')))

export interface RouterContext {
  queryClient: import('@tanstack/react-query').QueryClient
}

export const Route = createRootRouteWithContext<RouterContext>()({
  staleTime: Infinity,
  validateSearch: (search: Record<string, unknown>): { ui_locales?: string } => ({
    ui_locales: typeof search.ui_locales === 'string' ? search.ui_locales : undefined,
  }),
  beforeLoad: async ({ search }) => ({
    locale: await loadRootLocale({
      data: { uiLocales: search.ui_locales },
    }),
  }),
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
  errorComponent: RootError,
  notFoundComponent: RootNotFound,
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

function useRootLocale() {
  return useRouterState({
    select: (state) => resolveLocale({
      uiLocales: [...state.matches].reverse().flatMap((match) => [
        (match.loaderData as { locale?: string } | undefined)?.locale ?? '',
        (match.context as { locale?: string } | undefined)?.locale ?? '',
      ]),
    }),
  })
}

function RootNotFound() {
  const locale = useRootLocale()
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <section className="w-full max-w-md rounded-field border border-border bg-surface p-6 shadow-sm">
        <h1 className="text-lg font-semibold">{translate(locale, 'pageNotFoundTitle')}</h1>
        <p className="mt-2 text-sm text-muted">
          {translate(locale, 'pageNotFoundDescription')}
        </p>
        <a className="mt-5 inline-flex min-h-10 items-center rounded-field bg-accent px-4 py-2 text-sm font-medium text-accent-foreground" href="/">
          {translate(locale, 'pageNotFoundReturn')}
        </a>
      </section>
    </main>
  )
}

function RootError(_props: ErrorComponentProps) {
  const locale = useRootLocale()
  const retryHref = useRouterState({ select: (state) => state.location.href })

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <div className="w-full max-w-md rounded-field border border-border bg-surface p-6 shadow-sm">
        <h1 className="text-lg font-semibold">{translate(locale, 'unableToContinue')}</h1>
        <p className="mt-2 text-sm text-muted">
          {translate(locale, 'temporaryError')}
        </p>
        <a className="mt-5 inline-flex rounded-field bg-accent px-4 py-2 text-sm font-medium text-accent-foreground" href={retryHref}>
          {translate(locale, 'tryAgain')}
        </a>
      </div>
    </main>
  )
}

function RootDocument({ children }: { children: React.ReactNode }) {
  const locale = useRouterState({
    select: (state) => {
      for (const match of [...state.matches].reverse()) {
        const data = match.loaderData as { locale?: string } | undefined
        if (data?.locale) return data.locale
      }
      for (const match of [...state.matches].reverse()) {
        const context = match.context as { locale?: string } | undefined
        if (context?.locale) return context.locale
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
