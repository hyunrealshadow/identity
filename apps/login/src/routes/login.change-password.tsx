import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import {
  errorMessage,
  identityJson,
  isTerminalLoginError,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'
import {
  loginChallengeDestination,
  loginPasswordChangePath,
} from '#/modules/auth/lib/login-navigation'
import { submitPasswordChange } from '#/modules/auth/lib/password-change.server'
import { PasswordChangePageView } from '#/modules/auth/pages/login-change-password-page'

interface PasswordChangeSearch {
  login_id?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadPasswordChangePage = createServerFn({ method: 'GET' })
  .validator(
    (data: { loginId: string; restart?: string; uiLocales?: string }) => data,
  )
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginPasswordChangePath)
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
      restartRequired:
        data.restart === 'required' || data.restart === 'unavailable',
      restartUnavailable: data.restart === 'unavailable',
      redirectTo: undefined as string | undefined,
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
      if (page.status.status !== 'password_change_required') {
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            page.status.continue_uri ??
            page.status.challenge_uri ??
            ((page.status.status === 'mfa_required' ||
              page.status.status === 'identifier_verified') &&
            page.status.preferred_credential_type
              ? loginChallengeDestination(
                  loginId,
                  page.status.preferred_credential_type,
                  uiLocales,
                )
              : `/login?${search}`),
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

export const Route = createFileRoute('/login/change-password')({
  validateSearch: (search): PasswordChangeSearch => ({
    login_id: optionalString(search.login_id),
    restart: optionalString(search.restart),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps }) => {
    const page = await loadPasswordChangePage({ data: deps })
    if (page.redirectTo) {
      throw redirect({
        href: withUiLocales(page.redirectTo, page.uiLocales),
        reloadDocument: true,
      })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitPasswordChange(request),
    },
  },
  component: PasswordChangeRoute,
})

function PasswordChangeRoute() {
  const data = Route.useLoaderData()
  return <PasswordChangePageView data={data} />
}
