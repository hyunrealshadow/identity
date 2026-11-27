import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthorizationErrorView } from '#/components/authorization-error-view'
import { requestLocale } from '#/lib/i18n.server'

const loadCallbackErrorPage = createServerFn({ method: 'GET' }).handler(
  () => ({ locale: requestLocale() }),
)

export const Route = createFileRoute('/callback')({
  headers: () => ({
    'Cache-Control': 'no-store',
    // Callback URLs carry authorization parameters; never leak them in Referer.
    'Referrer-Policy': 'no-referrer',
  }),
  loader: () => loadCallbackErrorPage(),
  server: {
    handlers: {
      GET: async ({ request, next }) => {
        const { handleCallbackGet } = await import(
          '#/modules/auth/lib/callback-route.server'
        )
        return handleCallbackGet({ request, next })
      },
    },
  },
  component: CallbackErrorPage,
})

function CallbackErrorPage() {
  const { locale } = Route.useLoaderData()
  return <AuthorizationErrorView locale={locale} />
}
