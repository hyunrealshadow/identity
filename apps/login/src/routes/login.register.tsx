import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import {
  errorMessage,
  identityJson,
  isTerminalLoginError,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
  RegistrationCheckResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { loginRegisterPath } from '#/modules/auth/lib/login-navigation'
import { submitRegistration } from '#/modules/auth/lib/registration.server'
import { RegisterPageView } from '#/modules/auth/pages/login-register-page'

interface RegisterSearch {
  login_id?: string
  /** The token of an emailed registration link. */
  token?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadRegisterPage = createServerFn({ method: 'GET' })
  .validator(
    (data: {
      loginId: string
      token?: string
      restart?: string
      uiLocales?: string
    }) => data,
  )
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginRegisterPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      status: undefined as LoginStatusResponse | undefined,
      csrfToken: '',
      loginId,
      locale,
      uiLocales,
      error: flash?.fields ? undefined : flash?.message,
      fields: flash?.fields ?? {},
      values: flash?.values ?? {},
      linkEmail: undefined as string | undefined,
      linkError: undefined as string | undefined,
      restartRequired:
        data.restart === 'required' || data.restart === 'unavailable',
      restartUnavailable: data.restart === 'unavailable',
    }
    if (!loginId) {
      return { ...page, error: page.error ?? translate(locale, 'missingLogin') }
    }

    try {
      page.csrfToken = (
        await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')
      ).csrf_token
      if (page.restartRequired) {
        return {
          ...page,
          error:
            page.error ??
            translate(
              locale,
              page.restartUnavailable
                ? 'authorizationRestartUnavailable'
                : 'challengeExpiredDescription',
            ),
        }
      }
      page.status = await identityJson<LoginStatusResponse>(
        `/api/auth/login/${encodeURIComponent(loginId)}`,
      )
      if (page.status.status === 'expired') {
        return {
          ...page,
          restartRequired: true,
          error: translate(locale, 'challengeExpiredDescription'),
        }
      }
      if (data.token) {
        try {
          const link = await identityJson<RegistrationCheckResponse>(
            '/api/auth/login/registration/check',
            {
              method: 'POST',
              csrfToken: page.csrfToken,
              body: { id: loginId, token: data.token },
            },
          )
          page.linkEmail = link.email
        } catch (error) {
          if (isTerminalLoginError(error)) throw error
          page.linkError = errorMessage(error, locale)
        }
      }
      return page
    } catch (error) {
      if (isTerminalLoginError(error)) {
        return {
          ...page,
          restartRequired: true,
          error:
            page.error ?? translate(locale, 'challengeExpiredDescription'),
        }
      }
      return { ...page, error: page.error ?? errorMessage(error, locale) }
    }
  })

/**
 * Create an account from the identifier step. The address comes first: an
 * emailed link verifies it, and only then are a username and password
 * chosen. The page says the same thing whether or not the address already
 * has an account.
 */
export const Route = createFileRoute('/login/register')({
  validateSearch: (search): RegisterSearch => ({
    login_id: optionalString(search.login_id),
    token: optionalString(search.token),
    restart: optionalString(search.restart),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    token: search.token,
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadRegisterPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // A link's token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: ({ request }) => submitRegistration(request),
    },
  },
  component: RegisterRoute,
})

function RegisterRoute() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  return <RegisterPageView data={data} token={search.token} />
}
