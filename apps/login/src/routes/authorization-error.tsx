import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { buttonVariants } from '@identity/ui/components/button'
import { Link, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { CircleAlert } from 'lucide-react'

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
      <Alert variant="destructive">
        <CircleAlert aria-hidden="true" />
        <AlertTitle>
          <code className="break-all text-sm">
            {search.error ?? 'invalid_request'}
          </code>
        </AlertTitle>
        <AlertDescription>
          {search.error_description ?? t('oauthCallbackInvalid')}
        </AlertDescription>
      </Alert>
      <Link
        to="/"
        className={buttonVariants({ className: 'mt-6 w-full' })}
      >
        {t('authorizationRetry')}
      </Link>
    </AuthShell>
  )
}
