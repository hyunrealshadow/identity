import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { errorMessage, identityJson } from '#/lib/identity.server'
import type { ConsentPageData } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { submitConsentPost } from '#/modules/consent/lib/consent-route.server'
import {
  ConsentPageView,
  type ConsentSearch,
} from '#/modules/consent/pages/consent-page'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadConsentPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/consent')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''

    if (!loginId) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        consent: undefined,
        locale,
        uiLocales,
        error: flash?.message ?? translate(locale, 'missingConsent'),
      }
    }

    try {
      const consent = await identityJson<ConsentPageData>(
        `/oauth2/consent?login_id=${encodeURIComponent(loginId)}`,
      )
      return {
        consent,
        locale: requestLocale(uiLocales.split(' ')),
        uiLocales,
        error: flash?.message,
      }
    } catch (error) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        consent: undefined,
        locale,
        uiLocales,
        error: flash?.message ?? errorMessage(error, locale),
      }
    }
  })

export const Route = createFileRoute('/consent')({
  validateSearch: (search): ConsentSearch => ({
    login_id: optionalString(search.login_id),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadConsentPage({ data: deps }),
  server: {
    handlers: {
      POST: ({ request }) => submitConsentPost(request),
    },
  },
  component: ConsentRoute,
})

function ConsentRoute() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  return <ConsentPageView data={data} search={search} />
}
