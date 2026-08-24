import {
  Alert,
  Button,
  FieldError,
  Input,
  Label,
  TextField,
} from '@heroui/react'
import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, ChevronDown, Eye, EyeOff } from 'lucide-react'
import { useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { RecoveryCodeInput, TotpInput } from '#/components/totp-input'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
  isTerminalLoginError,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  ChallengeResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import {
  consumeFormFlash,
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'

interface ChallengeSearch {
  login_id?: string
  credential_type?: string
  error?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

function challengeDestination(
  request: Request,
  loginId: string,
  credentialType: string,
  uiLocales?: string,
) {
  const destination = new URL('/login/challenge', request.url)
  if (loginId) destination.searchParams.set('login_id', loginId)
  destination.searchParams.set('credential_type', credentialType)
  if (uiLocales) destination.searchParams.set('ui_locales', uiLocales)
  return destination.toString()
}

const loadChallengePage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/login/challenge')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales || flash?.values.ui_locales || ''
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
      }
    }

    try {
      const [active, status] = await Promise.all([
        identityJson<ActiveAccountsResponse>('/api/auth/sessions/active'),
        identityJson<LoginStatusResponse>(
          `/api/auth/login/${encodeURIComponent(loginId)}`,
        ),
      ])
      return {
        status,
        csrfToken: active.csrf_token,
        loginId,
        locale: requestLocale(uiLocales ? uiLocales.split(' ') : status.ui_locales),
        uiLocales: uiLocales || status.ui_locales?.join(' ') || '',
        error: pageError,
        fieldError: credentialError,
      }
    } catch (error) {
      if (isTerminalLoginError(error)) {
        throw redirect({ to: '/login' })
      }
      const locale = requestLocale()
      return {
        status: undefined,
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? errorMessage(error, locale),
        fieldError: credentialError,
      }
    }
  })

export const Route = createFileRoute('/login/challenge')({
  validateSearch: (search): ChallengeSearch => ({
    login_id: optionalString(search.login_id),
    credential_type: optionalString(search.credential_type),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadChallengePage({ data: deps }),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const loginId = String(form.get('login_id') ?? '')
        const credentialType = String(
          form.get('credential_type') ?? 'password',
        )
        const credential = String(
          form.get('credential') ?? form.get('totp') ?? form.get('otp') ?? '',
        )
        const csrfToken = String(form.get('csrf_token') ?? '')
        const locale = formLocale(request, form.get('ui_locales'))
        const uiLocales = optionalString(form.get('ui_locales'))

        if (!loginId || !credential) {
          return formErrorResponse(
            request,
            '/login/challenge',
            translate(locale, 'challengeRequired'),
            { login_id: loginId, credential_type: credentialType, ui_locales: uiLocales },
            loginId ? 'credential' : undefined,
            challengeDestination(request, loginId, credentialType, uiLocales),
          )
        }

        try {
          const result = await identityJson<ChallengeResponse>(
            '/api/auth/login/challenge',
            {
              method: 'POST',
              csrfToken,
              body: {
                id: loginId,
                credential_type: credentialType,
                credential,
              },
            },
          )

          if (result.status === 'mfa_required') {
            const destination = new URL('/login/challenge', request.url)
            destination.searchParams.set('login_id', loginId)
            destination.searchParams.set('credential_type', 'otp')
            if (uiLocales) destination.searchParams.set('ui_locales', uiLocales)
            return navigationResponse(request, destination.toString())
          }

          if (!result.continue_uri) {
            throw new Error(translate(locale, 'continuationMissing'))
          }
          return navigationResponse(request, result.continue_uri)
        } catch (error) {
          if (isTerminalLoginError(error)) {
            return navigationResponse(request, '/login')
          }
          const values = {
            login_id: loginId,
            credential_type: credentialType,
            ui_locales: uiLocales,
          }
          if (error instanceof IdentityApiError && error.fields.length > 0) {
            return formValidationErrorResponse(
              request,
              '/login/challenge',
              error.message,
              values,
              Object.fromEntries(
                error.fields.map((fieldError) => [
                  fieldError.field,
                  fieldError.message,
                ]),
              ),
              challengeDestination(request, loginId, credentialType, uiLocales),
            )
          }
          return formErrorResponse(
            request,
            '/login/challenge',
            errorMessage(error, locale),
            values,
            undefined,
            challengeDestination(request, loginId, credentialType, uiLocales),
          )
        }
      },
    },
  },
  component: ChallengePage,
})

function ChallengePage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const [showPassword, setShowPassword] = useState(false)
  const [credentialError, setCredentialError] = useState(data.fieldError)
  const loginId = data.loginId
  const credentialType =
    search.credential_type === 'otp' ||
    search.credential_type === 'recovery_code'
      ? search.credential_type
      : 'password'
  const isOtp = credentialType === 'otp'
  const isRecoveryCode = credentialType === 'recovery_code'
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const alternativeMethods = credentialType === 'password'
    ? []
    : [
        { credentialType: 'otp', label: t('useAuthenticatorCode') },
        { credentialType: 'recovery_code', label: t('useRecoveryCode') },
      ].filter(
        (method) =>
          method.credentialType !== credentialType &&
          data.status?.credential_types.includes(method.credentialType),
      )
  const canSwitchAccount = !data.status?.requires_reauthentication
  const visibleError = search.error ?? data.error
  const user = data.status?.user

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      title={
        isRecoveryCode
          ? t('recoveryCodeTitle')
          : isOtp
            ? t('otpTitle')
            : t('passwordTitle')
      }
      description={
        isRecoveryCode
          ? t('recoveryCodeDescription')
          : isOtp
          ? t('otpDescription')
          : t('passwordDescription')
      }
    >
      {user ? (
        <div className="mb-6 flex items-center gap-3 rounded-xl border border-border bg-surface-secondary p-3">
          <AccountAvatar name={user.name} picture={user.picture} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{user.name}</p>
            <p className="truncate text-xs text-muted">{user.email}</p>
          </div>
        </div>
      ) : null}

      {visibleError ? (
        <Alert
          status="danger"
          className="auth-alert mb-5"
        >
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('verificationFailed')}</Alert.Title>
            <Alert.Description>{visibleError}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      <ProgressiveForm
        action="/login/challenge"
        className="progressive-form space-y-5"
        enhancementErrorMessage={t('enhancedNavigationError')}
        noValidate
      >
        <input type="hidden" name="login_id" value={loginId} />
        <input
          type="hidden"
          name="credential_type"
          value={credentialType}
        />
        <input
          type="hidden"
          name="csrf_token"
          value={data.csrfToken}
        />
        <input type="hidden" name="ui_locales" value={data.uiLocales} />

        {isOtp ? (
          <div className="grid gap-2">
            <Label>{t('otp')}</Label>
            <TotpInput
              name="totp"
              type="text"
              required
              className="mx-auto"
              isInvalid={Boolean(credentialError)}
              aria-invalid={Boolean(credentialError)}
              aria-describedby={credentialError ? 'login-otp-error' : undefined}
              onChange={() => setCredentialError(undefined)}
            />
            {credentialError ? (
              <p id="login-otp-error" className="text-xs text-danger">
                {credentialError}
              </p>
            ) : null}
          </div>
        ) : isRecoveryCode ? (
          <div className="grid gap-2">
            <Label>{t('recoveryCode')}</Label>
            <RecoveryCodeInput
              name="credential"
              type="text"
              required
              className="mx-auto"
              isInvalid={Boolean(credentialError)}
              aria-invalid={Boolean(credentialError)}
              aria-describedby={
                credentialError ? 'login-recovery-code-error' : undefined
              }
              onChange={() => setCredentialError(undefined)}
            />
            {credentialError ? (
              <p id="login-recovery-code-error" className="text-xs text-danger">
                {credentialError}
              </p>
            ) : null}
          </div>
        ) : (
          <TextField isRequired fullWidth name="credential" isInvalid={!!credentialError}>
            <Label>{t('password')}</Label>
            <div className="relative">
              <Input
                autoFocus
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                className="pr-12"
                onChange={() => setCredentialError(undefined)}
              />
              <Button
                type="button"
                isIconOnly
                variant="ghost"
                aria-label={showPassword ? t('hidePassword') : t('showPassword')}
                className="absolute right-1 top-1/2 -translate-y-1/2"
                onPress={() => setShowPassword((value) => !value)}
              >
                {showPassword ? (
                  <EyeOff className="size-4" aria-hidden="true" />
                ) : (
                  <Eye className="size-4" aria-hidden="true" />
                )}
              </Button>
            </div>
            <FieldError>{credentialError}</FieldError>
          </TextField>
        )}

        <SubmitButton fullWidth>
          {isOtp || isRecoveryCode ? t('verify') : t('login')}
        </SubmitButton>
      </ProgressiveForm>

      {alternativeMethods.length ? (
        <details className="auth-methods group mt-6 border-t border-border">
          <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between pt-4 text-xs font-medium text-muted transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
            {t('otherVerificationMethods')}
            <ChevronDown
              className="size-4 transition-transform group-open:rotate-180"
              aria-hidden="true"
            />
          </summary>
          <div className="auth-method-options mt-1 grid gap-1 pb-1">
            {alternativeMethods.map((method) => (
              <a
                key={method.credentialType}
                href={`/login/challenge?login_id=${encodeURIComponent(loginId)}&credential_type=${method.credentialType}${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
                className="flex min-h-9 items-center justify-between rounded-lg bg-surface-secondary px-3 text-sm font-medium text-foreground transition-colors hover:bg-surface-tertiary"
              >
                {method.label}
              </a>
            ))}
          </div>
        </details>
      ) : null}

      {canSwitchAccount ? (
        <a
          href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
          className="auth-link mx-auto mt-6 flex w-fit items-center justify-center gap-1.5 text-sm font-semibold text-accent"
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('switchAccount')}
        </a>
      ) : null}
    </AuthShell>
  )
}
