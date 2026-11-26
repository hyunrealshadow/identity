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
  PasswordResetStatusResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { loginPasswordResetPath } from '#/modules/auth/lib/login-navigation'
import { submitPasswordReset } from '#/modules/auth/lib/password-reset.server'
import { PasswordResetPageView } from '#/modules/auth/pages/login-reset-password-page'

interface PasswordResetSearch {
  login_id?: string
  /** The token of an emailed reset link. */
  token?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadPasswordResetPage = createServerFn({ method: 'GET' })
  .validator(
    (data: {
      loginId: string
      token?: string
      restart?: string
      uiLocales?: string
    }) => data,
  )
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginPasswordResetPath)
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
      if (data.token && !flash) {
        try {
          await identityJson<PasswordResetStatusResponse>(
            '/api/auth/login/password-reset/check',
            {
              method: 'POST',
              csrfToken: page.csrfToken,
              body: { id: loginId, token: data.token },
            },
          )
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

export const Route = createFileRoute('/login/reset-password')({
  validateSearch: (search): PasswordResetSearch => ({
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
  loader: ({ deps }) => loadPasswordResetPage({ data: deps }),
  server: {
    handlers: {
      POST: ({ request }) => submitPasswordReset(request),
    },
  },
  component: PasswordResetRoute,
})

function PasswordResetRoute() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  return <PasswordResetPageView data={data} token={search.token} />
}
