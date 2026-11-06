import { RouterProvider } from '@tanstack/react-router'
import { QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import './styles.css'
import { FullPageLoading } from '#/components/full-page-loading'
import { ConfigError, loadRuntimeConfig } from '#/lib/config'
import { queryClient } from '#/lib/graphql/query-client'
import { resolveBrowserLocale, translate } from '#/lib/i18n'
import { createAppRouter } from './router'

const container = document.getElementById('root')
if (!container) throw new Error('Root container is missing')

const root = createRoot(container)

function StartupLoading() {
  const locale = resolveBrowserLocale()
  document.documentElement.lang = locale
  return <FullPageLoading label={translate(locale, 'startupLoading')} />
}

function StartupError({ error }: { error: unknown }) {
  const locale = resolveBrowserLocale()
  document.documentElement.lang = locale
  const fetchFailed =
    !(error instanceof ConfigError) ||
    error.code === 'config_unavailable' ||
    error.code === 'config_not_json'

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <div className="w-full max-w-lg rounded-field border border-border bg-surface p-6 shadow-sm">
        <h1 className="text-lg font-semibold">{translate(locale, 'startupConfigTitle')}</h1>
        <p className="mt-2 text-sm leading-6 text-muted">
          {translate(locale, 'startupConfigDescription')}
        </p>
        <p className="mt-3 text-sm leading-6 text-muted">
          {translate(locale, fetchFailed ? 'startupConfigFetch' : 'startupConfigInvalid')}
        </p>
        <button
          type="button"
          className="mt-5 rounded-field bg-accent px-4 py-2 text-sm font-medium text-accent-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
          onClick={() => window.location.reload()}
        >
          {translate(locale, 'startupConfigRetry')}
        </button>
      </div>
    </main>
  )
}

root.render(
  <StrictMode>
    <StartupLoading />
  </StrictMode>,
)

loadRuntimeConfig()
  .then((config) => {
    document.title = config.displayName
    const router = createAppRouter(config)
    root.render(
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </StrictMode>,
    )
  })
  .catch((error: unknown) => {
    root.render(
      <StrictMode>
        <StartupError error={error} />
      </StrictMode>,
    )
  })
