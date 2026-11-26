import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
  MfaEnrollmentResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'
import {
  loginChallengeDestination,
  loginMfaSetupPath,
} from '#/modules/auth/lib/login-navigation'
import { submitLoginMfaSetup } from '#/modules/mfa/lib/login-mfa-setup.server'
import {
  MfaSetupPageView,
  type MfaSetupSearch,
} from '#/modules/mfa/pages/login-mfa-setup-page'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

async function qrCodeSvg(uri: string) {
  try {
    const { default: QRCode } = await import('qrcode')
    return await QRCode.toString(uri, {
      type: 'svg',
      margin: 0,
      errorCorrectionLevel: 'M',
      color: { dark: '#18181b', light: '#ffffff' },
    })
  } catch {
    // The setup key and authenticator link remain available.
    return undefined
  }
}

const loadMfaSetupPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; restart?: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginMfaSetupPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const codeError =
      flash?.fields?.code ?? (flash?.field === 'code' ? flash.message : undefined)
    const page = {
      loginId,
      locale,
      uiLocales,
      csrfToken: '',
      status: undefined as LoginStatusResponse | undefined,
      enrollment: undefined as MfaEnrollmentResponse | undefined,
      qrCode: undefined as string | undefined,
      error: codeError ? undefined : flash?.message,
      codeError,
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
        status.enrollment_method === 'passkey'
      ) {
        // The interaction moved on (completed elsewhere, or a factor was
        // enrolled meanwhile) or asks for a passkey: continue wherever it now
        // stands.
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            status.continue_uri ??
            (status.enrollment_method === 'passkey'
              ? status.challenge_uri
              : undefined) ??
            (status.status === 'mfa_required' && status.preferred_credential_type
              ? loginChallengeDestination(
                  loginId,
                  status.preferred_credential_type,
                  uiLocales,
                )
              : `/login?${search}`),
        }
      }
      const enrollment = await identityJson<MfaEnrollmentResponse>(
        '/api/auth/login/mfa-enrollment',
        {
          method: 'POST',
          csrfToken: active.csrf_token,
          body: { id: loginId },
        },
      )
      return {
        ...page,
        enrollment,
        qrCode: await qrCodeSvg(enrollment.otp_auth_uri),
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

export const Route = createFileRoute('/login/mfa-setup')({
  validateSearch: (search): MfaSetupSearch => ({
    login_id: optionalString(search.login_id),
    restart: optionalString(search.restart),
    // Which pending enrollment's recovery codes were saved; a plain query
    // parameter so moving on to the authenticator works without JavaScript.
    recovery_saved: optionalString(search.recovery_saved),
    step: search.step === 'verify' ? 'verify' : undefined,
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps }) => {
    const page = await loadMfaSetupPage({ data: deps })
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
      POST: ({ request }) => submitLoginMfaSetup(request),
    },
  },
  component: MfaSetupRoute,
})

function MfaSetupRoute() {
  const data = Route.useLoaderData()
  const search = Route.useSearch()
  return <MfaSetupPageView data={data} search={search} />
}
