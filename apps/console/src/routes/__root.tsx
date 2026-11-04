import {
  Outlet,
  createRootRouteWithContext,
  type ErrorComponentProps,
} from '@tanstack/react-router'

import { BASE_HREF } from '#/lib/base-path'
import { AuthProvider } from '#/lib/auth/context'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider, resolveCurrentLocale, translate } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'

export interface RouterContext {
  config: RuntimeConfig
}

function RootComponent() {
  const { config } = Route.useRouteContext()
  return (
    <RuntimeConfigProvider config={config}>
      <LocaleProvider>
        <AuthProvider>
          <Outlet />
        </AuthProvider>
      </LocaleProvider>
    </RuntimeConfigProvider>
  )
}

function NotFoundComponent() {
  const locale = resolveCurrentLocale()
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl flex-col justify-center p-6">
      <div
        role="alert"
        className="rounded-field border border-border bg-surface p-6 shadow-sm"
      >
        <h1 className="text-lg font-semibold">{translate(locale, 'notFoundTitle')}</h1>
        <p className="mt-2 text-sm text-muted">
          {translate(locale, 'notFoundDescription')}
        </p>
        <a
          href={BASE_HREF}
          className="mt-5 inline-flex min-h-10 items-center rounded-field bg-accent px-4 py-2 text-sm font-medium text-accent-foreground"
        >
          {translate(locale, 'backToDashboard')}
        </a>
      </div>
    </main>
  )
}

function RootErrorComponent(_props: ErrorComponentProps) {
  const locale = resolveCurrentLocale()
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl flex-col justify-center p-6">
      <div role="alert" className="rounded-field border border-border bg-surface p-6 shadow-sm">
        <h1 className="text-lg font-semibold">{translate(locale, 'errorTitle')}</h1>
        <p className="mt-2 text-sm text-muted">
          {translate(locale, 'errorDescriptionFallback')}
        </p>
        <button
          type="button"
          className="mt-4 rounded-field bg-accent px-4 py-2 text-sm font-medium text-accent-foreground"
          onClick={() => window.location.reload()}
        >
          {translate(locale, 'retry')}
        </button>
      </div>
    </main>
  )
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: RootErrorComponent,
})
