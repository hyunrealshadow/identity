import { Link, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthShell } from '#/components/auth-shell'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

interface AuthorizationErrorSearch {
  error?: string
  error_description?: string
}

function boundedString(value: unknown, maxLength: number) {
  return typeof value === 'string' && value.length > 0
    ? value.slice(0, maxLength)
    : undefined
}

const loadAuthorizationErrorPage = createServerFn({ method: 'GET' }).handler(
  () => ({ locale: requestLocale() }),
)

export const Route = createFileRoute('/authorization-error')({
  validateSearch: (search): AuthorizationErrorSearch => ({
    error: boundedString(search.error, 128),
    error_description: boundedString(search.error_description, 1024),
  }),
  loader: () => loadAuthorizationErrorPage(),
  component: AuthorizationErrorPage,
})

function AuthorizationErrorPage() {
  const { locale } = Route.useLoaderData()
  const search = Route.useSearch()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('authorizationFailedTitle')}
      description={t('authorizationFailedDescription')}
    >
      <div className="rounded-xl border border-danger/30 bg-danger/10 p-4">
        <code className="block break-all text-sm font-semibold text-danger">
          {search.error ?? 'invalid_request'}
        </code>
        <p className="mt-2 text-sm leading-6 text-foreground">
          {search.error_description ?? t('oauthCallbackInvalid')}
        </p>
      </div>
      <Link
        to="/"
        className="mt-6 flex min-h-10 w-full items-center justify-center rounded-field bg-accent px-4 text-sm font-semibold text-accent-foreground transition-opacity hover:opacity-90"
      >
        {t('authorizationRetry')}
      </Link>
    </AuthShell>
  )
}
