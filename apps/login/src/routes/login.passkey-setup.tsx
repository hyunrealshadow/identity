import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  ChallengeResponse,
  LoginStatusResponse,
  PasskeyEnrollmentResponse,
} from '#/lib/identity-types'
import { translate, type Locale } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'
import {
  loginChallengeDestination,
  loginPasskeySetupPath,
} from '#/modules/auth/lib/login-navigation'
import { submitLoginPasskeySetup } from '#/modules/passkey/lib/login-passkey-setup.server'
import { PasskeySetupPageView } from '#/modules/passkey/pages/login-passkey-setup-page'

interface PasskeySetupSearch {
  login_id?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadPasskeySetupPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; restart?: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginPasskeySetupPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      loginId,
      locale,
      uiLocales,
      csrfToken: '',
      status: undefined as LoginStatusResponse | undefined,
      recoveryCodes: [] as Array<string>,
      // WebAuthn options stay JSON so the loader result remains serializable.
      optionsJson: undefined as string | undefined,
      error: flash?.message,
      restartRequired: false,
      restartUnavailable: false,
      redirectTo: undefined as string | undefined,
    }
    if (!loginId) return { ...page, error: page.error ?? translate(locale, 'missingLogin') }

    try {
      const active = await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')
      page.csrfToken = active.csrf_token
      if (data.restart === 'required' || data.restart === 'unavailable') {
        const restartUnavailable = data.restart === 'unavailable'
        return {
          ...page,
          restartRequired: true,
          restartUnavailable,
          error:
            page.error ??
            translate(
              locale,
              restartUnavailable
                ? 'authorizationRestartUnavailable'
                : 'challengeExpiredDescription',
            ),
        }
      }
      const status = await identityJson<LoginStatusResponse>(
        `/api/auth/login/${encodeURIComponent(loginId)}`,
      )
      page.status = status
      if (status.status === 'expired') {
        return {
          ...page,
          restartRequired: true,
          error: translate(locale, 'challengeExpiredDescription'),
        }
      }
      if (
        status.status !== 'mfa_enrollment_required' ||
        status.enrollment_method !== 'passkey'
      ) {
        // The interaction moved on, or asks for another credential: continue
        // wherever it now stands.
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            status.continue_uri ??
            status.challenge_uri ??
            (status.status === 'mfa_required' && status.preferred_credential_type
              ? loginChallengeDestination(
                  loginId,
                  status.preferred_credential_type,
                  uiLocales,
                )
              : `/login?${search}`),
        }
      }
      const enrollment = await identityJson<PasskeyEnrollmentResponse>(
        '/api/auth/login/passkey-enrollment',
        { method: 'POST', csrfToken: active.csrf_token, body: { id: loginId } },
      )
      return {
        ...page,
        recoveryCodes: enrollment.recovery_codes,
        optionsJson: JSON.stringify(enrollment.options),
      }
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

const confirmPasskey = createServerFn({ method: 'POST' })
  .validator(
    (data: {
      loginId: string
      csrfToken: string
      challengeId: string
      name: string
      credential: string
      locale: Locale
    }) => data,
  )
  .handler(async ({ data }) => {
    try {
      const result = await identityJson<ChallengeResponse>(
        '/api/auth/login/passkey-enrollment/confirm',
        {
          method: 'POST',
          csrfToken: data.csrfToken,
          body: {
            id: data.loginId,
            challenge_id: data.challengeId,
            name: data.name,
            credential: JSON.parse(data.credential) as unknown,
          },
        },
      )
      return { registered: result.status === 'mfa_required' }
    } catch (error) {
      return { error: errorMessage(error, data.locale) }
    }
  })

export const Route = createFileRoute('/login/passkey-setup')({
  validateSearch: (search): PasskeySetupSearch => ({
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
    const page = await loadPasskeySetupPage({ data: deps })
    if (page.redirectTo) {
      throw redirect({
        href: withUiLocales(page.redirectTo, deps.uiLocales),
        reloadDocument: true,
      })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitLoginPasskeySetup(request),
    },
  },
  component: PasskeySetupRoute,
})

function PasskeySetupRoute() {
  const data = Route.useLoaderData()
  return (
    <PasskeySetupPageView
      data={data}
      onConfirmPasskey={(input) => confirmPasskey({ data: input })}
    />
  )
}
