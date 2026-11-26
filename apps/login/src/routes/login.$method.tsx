import { createFileRoute, notFound, redirect } from '@tanstack/react-router'
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
import { submitLoginMethod } from '#/modules/auth/lib/login-method.server'
import {
  loginChallengeDestination,
  loginCredentialType,
  loginMethodPath,
} from '#/modules/auth/lib/login-navigation'
import {
  ChallengePageView,
  type ChallengeSearch,
} from '#/modules/auth/pages/login-challenge-page'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadChallengePage = createServerFn({ method: 'GET' })
  .validator(
    (data: {
      loginId: string
      method: string
      restart?: string
      uiLocales?: string
    }) => data,
  )
  .handler(async ({ data }) => {
    const credentialType = loginCredentialType(data.method)
    if (!credentialType) throw notFound()
    const flash = consumeFormFlash(loginMethodPath(credentialType))
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const credentialError =
      flash?.fields?.credential ??
      (flash?.field === 'credential' ? flash.message : undefined)
    const pageError = credentialError ? undefined : flash?.message

    if (!loginId) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        status: undefined,
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? translate(locale, 'missingLogin'),
        fieldError: credentialError,
        restartRequired: false,
        restartUnavailable: false,
      }
    }

    let csrfToken = ''
    try {
      const active = await identityJson<ActiveAccountsResponse>(
        '/api/auth/sessions/active',
      )
      csrfToken = active.csrf_token
      if (data.restart === 'required' || data.restart === 'unavailable') {
        const locale = requestLocale(uiLocales.split(' '))
        const restartUnavailable = data.restart === 'unavailable'
        return {
          status: undefined,
          csrfToken,
          loginId,
          locale,
          uiLocales,
          error:
            pageError ??
            translate(
              locale,
              restartUnavailable
                ? 'authorizationRestartUnavailable'
                : 'challengeExpiredDescription',
            ),
          fieldError: undefined,
          restartRequired: true,
          restartUnavailable,
        }
      }
      const status = await identityJson<LoginStatusResponse>(
        `/api/auth/login/${encodeURIComponent(loginId)}`,
      )
      const locale = requestLocale(uiLocales.split(' '))
      const restartRequired = status.status === 'expired'
      return {
        status,
        csrfToken,
        loginId,
        locale,
        uiLocales,
        error: restartRequired
          ? translate(locale, 'challengeExpiredDescription')
          : pageError,
        fieldError: credentialError,
        restartRequired,
        restartUnavailable: false,
      }
    } catch (error) {
      if (isTerminalLoginError(error)) {
        const locale = requestLocale(uiLocales.split(' '))
        return {
          status: undefined,
          csrfToken,
          loginId,
          locale,
          uiLocales,
          error: pageError ?? translate(locale, 'challengeExpiredDescription'),
          fieldError: undefined,
          restartRequired: true,
          restartUnavailable: false,
        }
      }
      const locale = requestLocale(uiLocales.split(' '))
      return {
        status: undefined,
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? errorMessage(error, locale),
        fieldError: credentialError,
        restartRequired: false,
        restartUnavailable: false,
      }
    }
  })

export const Route = createFileRoute('/login/$method')({
  validateSearch: (search): ChallengeSearch => ({
    login_id: optionalString(search.login_id),
    token: optionalString(search.token),
    error: optionalString(search.error),
    restart: optionalString(search.restart),
    notice: optionalString(search.notice),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps, params }) => {
    if (!loginCredentialType(params.method)) throw notFound()
    const page = await loadChallengePage({
      data: { ...deps, method: params.method },
    })
    if (
      page.status?.status === 'password_change_required' &&
      page.status.challenge_uri
    ) {
      throw redirect({
        href: withUiLocales(page.status.challenge_uri, page.uiLocales),
      })
    }
    if (
      params.method === 'password' &&
      page.status &&
      !page.status.credential_types.includes('password') &&
      page.status.preferred_credential_type
    ) {
      throw redirect({
        href: loginChallengeDestination(
          page.loginId,
          page.status.preferred_credential_type,
          page.uiLocales,
        ),
      })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request, params }) => submitLoginMethod(request, params.method),
    },
  },
  component: ChallengePage,
})

function ChallengePage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const credentialType = loginCredentialType(Route.useParams().method)!
  return (
    <ChallengePageView
      data={data}
      search={search}
      credentialType={credentialType}
    />
  )
}
