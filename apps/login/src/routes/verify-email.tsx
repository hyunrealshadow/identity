import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import {
  submitVerifyEmailPost,
  VERIFY_EMAIL_PATH,
} from '#/modules/auth/lib/verify-email-route.server'
import { VerifyEmailPageView } from '#/modules/auth/pages/verify-email-page'

interface VerifyEmailSearch {
  token?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadVerifyEmailPage = createServerFn({ method: 'GET' })
  .validator((data: { token: string }) => data)
  .handler(({ data }) => {
    const flash = consumeFormFlash(VERIFY_EMAIL_PATH)
    return {
      locale: requestLocale(),
      token: data.token,
      error: flash?.message,
    }
  })

/**
 * Where an emailed verification link lands. Opening the link only shows this
 * confirmation; the address is verified when the user continues, so a mail
 * scanner that fetches the link cannot use it. No account session is needed,
 * so the link also works on another device.
 */
export const Route = createFileRoute('/verify-email')({
  validateSearch: (search): VerifyEmailSearch => ({
    token: optionalString(search.token),
  }),
  loaderDeps: ({ search }) => ({ token: search.token ?? '' }),
  loader: ({ deps }) => loadVerifyEmailPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // The token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: ({ request }) => submitVerifyEmailPost(request),
    },
  },
  component: VerifyEmailRoute,
})

function VerifyEmailRoute() {
  const { locale, token, error } = Route.useLoaderData()
  return <VerifyEmailPageView locale={locale} token={token} error={error} />
}
