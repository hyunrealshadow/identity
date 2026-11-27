import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthorizationErrorView } from '#/components/authorization-error-view'
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

  return (
    <AuthorizationErrorView
      locale={locale}
      error={search.error}
      errorDescription={search.error_description}
    />
  )
}
