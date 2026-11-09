import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { createFileRoute, notFound, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, CircleAlert } from 'lucide-react'
import { useState } from 'react'

import { LoginMethodAlternatives } from '#/components/login-method-alternatives'
import { PasskeyLogin } from '#/components/passkey-login'
import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { GroupedCodeInput, TotpInput } from '#/components/totp-input'
import {
  errorMessage,
  identityJson,
  isTerminalLoginError,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import {
  consumeFormFlash,
} from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { submitLoginMethod } from '#/lib/login-method.server'
import { loginCredentialType, loginMethodPath, loginChallengeDestination } from '#/lib/login-navigation'

interface ChallengeSearch {
  login_id?: string
  error?: string
  restart?: string
  ui_locales?: string
}

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
      const locale = requestLocale(
        uiLocales.split(' '),
      )
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
    error: optionalString(search.error),
    restart: optionalString(search.restart),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps, params }) => {
    if (!loginCredentialType(params.method)) throw notFound()
    const page = await loadChallengePage({ data: { ...deps, method: params.method } })
    if (params.method === 'password' && page.status &&
        !page.status.credential_types.includes('password') &&
        page.status.preferred_credential_type) {
      throw redirect({ href: loginChallengeDestination(page.loginId, page.status.preferred_credential_type, page.uiLocales) })
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
  const [credentialError, setCredentialError] = useState(data.fieldError)
  const loginId = data.loginId
  const credentialType = loginCredentialType(Route.useParams().method)!
  const pathname = loginMethodPath(credentialType)
  const isPasskey = credentialType === 'passkey'
  const isOtp = credentialType === 'otp'
  const isRecoveryCode = credentialType === 'recovery_code'
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const canSwitchAccount = !data.status?.requires_reauthentication
  const visibleError = search.error ?? data.error
  const user = data.status?.user
  const restartRequired =
    search.restart === 'required' ||
    search.restart === 'unavailable' ||
    data.restartRequired
  const restartUnavailable =
    search.restart === 'unavailable' || data.restartUnavailable

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      tone={restartRequired ? 'danger' : 'default'}
      titleIcon={restartRequired ? <CircleAlert className="size-6" aria-hidden="true" /> : undefined}
      title={
        restartRequired
          ? t('challengeExpiredTitle')
          : isPasskey
          ? t('usePasskey')
          : isRecoveryCode
          ? t('recoveryCodeTitle')
          : isOtp
            ? t('otpTitle')
            : t('passwordTitle')
      }
      description={
        restartUnavailable
          ? t('authorizationRestartUnavailable')
          : restartRequired
          ? visibleError || t('challengeExpiredDescription')
          : isPasskey
          ? t('passkeySignInDescription')
          : isRecoveryCode
          ? t('recoveryCodeDescription')
          : isOtp
          ? t('otpDescription')
          : t('passwordDescription')
      }
    >
      <LoginClient client={data.status?.client} locale={data.locale} />
      {user ? (
        <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
          <AccountAvatar name={user.name} picture={user.picture} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{user.name}</p>
            <p className="truncate text-xs text-muted-foreground">{user.email}</p>
          </div>
        </div>
      ) : null}

      {visibleError && !restartRequired ? (
        <ErrorAlert className="mb-5" title={t('verificationFailed')} message={visibleError} />
      ) : null}

      {restartRequired && !restartUnavailable ? (
        <ProgressiveForm
          action={pathname}
          className="progressive-form"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="intent" value="restart" />
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
        </ProgressiveForm>
      ) : !restartRequired && !isPasskey ? (
        <ProgressiveForm
          action={pathname}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          noValidate
        >
        <input type="hidden" name="login_id" value={loginId} />
        <input
          type="hidden"
          name="csrf_token"
          value={data.csrfToken}
        />
        <input type="hidden" name="ui_locales" value={data.uiLocales} />

        {isOtp ? (
          <Field data-invalid={credentialError ? true : undefined}>
            <FieldLabel htmlFor="login-otp">{t('otp')}</FieldLabel>
            <TotpInput
              id="login-otp"
              name="totp"
              type="text"
              required
              autoFocus
              isInvalid={Boolean(credentialError)}
              aria-invalid={Boolean(credentialError)}
              aria-describedby={credentialError ? 'login-otp-error' : undefined}
              onChange={() => setCredentialError(undefined)}
            />
            {credentialError ? (
              <FieldError id="login-otp-error">{credentialError}</FieldError>
            ) : null}
          </Field>
        ) : isRecoveryCode ? (
          <Field data-invalid={credentialError ? true : undefined}>
            <FieldLabel htmlFor="login-recovery-code">{t('recoveryCode')}</FieldLabel>
            <GroupedCodeInput
              id="login-recovery-code"
              name="credential"
              type="text"
              required
              autoFocus
              isInvalid={Boolean(credentialError)}
              aria-invalid={Boolean(credentialError)}
              aria-describedby={
                credentialError ? 'login-recovery-code-error' : undefined
              }
              onChange={() => setCredentialError(undefined)}
            />
            {credentialError ? (
              <FieldError id="login-recovery-code-error">{credentialError}</FieldError>
            ) : null}
          </Field>
        ) : (
          <TextField
            required
            name="credential"
            label={t('password')}
            error={credentialError}
            autoFocus
            type="password"
            autoComplete="current-password"
            reveal={{ show: t('showPassword'), hide: t('hidePassword') }}
            onChange={() => setCredentialError(undefined)}
          />
        )}

        <SubmitButton fullWidth>
          {isOtp || isRecoveryCode ? t('verify') : t('login')}
        </SubmitButton>
        </ProgressiveForm>
      ) : null}

      {!restartRequired && isPasskey && (data.status?.status === 'identifier_verified' || data.status?.status === 'mfa_required') && data.status.credential_types.includes('passkey') ? (
        <PasskeyLogin loginId={loginId} csrfToken={data.csrfToken} locale={data.locale} uiLocales={data.uiLocales} primary />
      ) : null}

      {!restartRequired ? <LoginMethodAlternatives currentMethod={credentialType} status={data.status}
        loginId={loginId} uiLocales={data.uiLocales} locale={data.locale} /> : null}

      {!restartRequired && canSwitchAccount ? (
        <ProgressiveForm
          action={pathname}
          className="mt-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <SubmitButton
            name="intent"
            value="switch"
            variant="link"
            size="sm"
            className="mx-auto flex w-fit font-semibold"
          >
            <ArrowLeft className="size-4" aria-hidden="true" />
            {t('switchAccount')}
          </SubmitButton>
        </ProgressiveForm>
      ) : null}
    </AuthShell>
  )
}
