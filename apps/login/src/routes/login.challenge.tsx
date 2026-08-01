import {
  Alert,
  Avatar,
  Button,
  FieldError,
  Input,
  Label,
  TextField,
} from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, Eye, EyeOff } from 'lucide-react'
import { useState } from 'react'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
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
        locale: requestLocale(status.ui_locales),
        uiLocales: status.ui_locales?.join(' ') ?? '',
        error: pageError,
        fieldError: credentialError,
      }
    } catch (error) {
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
        const credential = String(form.get('credential') ?? '')
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
            )
          }
          return formErrorResponse(
            request,
            '/login/challenge',
            errorMessage(error, locale),
            values,
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
  const loginId = data.loginId
  const credentialType =
    search.credential_type === 'otp' ||
    search.credential_type === 'recovery_code'
      ? search.credential_type
      : 'password'
  const isOtp = credentialType === 'otp'
  const isRecoveryCode = credentialType === 'recovery_code'
  const visibleError = search.error ?? data.error
  const user = data.status?.user
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)

  return (
    <AuthShell
      lang={data.locale}
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
          <Avatar size="sm">
            <Avatar.Fallback>{user.name.slice(0, 1)}</Avatar.Fallback>
          </Avatar>
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

        {isOtp || isRecoveryCode ? (
          <TextField isRequired fullWidth name="credential" isInvalid={!!data.fieldError}>
            <Label>{isRecoveryCode ? t('recoveryCode') : t('otp')}</Label>
            <Input
              autoFocus
              inputMode={isRecoveryCode ? 'text' : 'numeric'}
              autoComplete={isRecoveryCode ? 'off' : 'one-time-code'}
              maxLength={isRecoveryCode ? 32 : 8}
              pattern={isRecoveryCode ? undefined : '[0-9]*'}
              placeholder={isRecoveryCode ? 'ABCD-EFGH-IJKL-MNOP' : '000000'}
              className="text-center font-mono text-xl tracking-[0.2em]"
            />
            <FieldError>{data.fieldError}</FieldError>
          </TextField>
        ) : (
          <TextField isRequired fullWidth name="credential" isInvalid={!!data.fieldError}>
            <Label>{t('password')}</Label>
            <div className="relative">
              <Input
                autoFocus
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                className="pr-12"
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
            <FieldError>{data.fieldError}</FieldError>
          </TextField>
        )}

        <SubmitButton fullWidth>
          {isOtp || isRecoveryCode ? t('verify') : t('login')}
        </SubmitButton>
      </ProgressiveForm>

      {isOtp || isRecoveryCode ? (
        <a
          href={`/login/challenge?login_id=${encodeURIComponent(loginId)}&credential_type=${isRecoveryCode ? 'otp' : 'recovery_code'}${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
          className="auth-link mx-auto mt-5 flex w-fit items-center justify-center text-sm font-semibold text-accent"
        >
          {isRecoveryCode ? t('useAuthenticatorCode') : t('useRecoveryCode')}
        </a>
      ) : null}

      <a
        href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
        className="auth-link mx-auto mt-5 flex w-fit items-center justify-center gap-1.5 text-sm font-semibold text-accent"
      >
        <ArrowLeft className="size-4" aria-hidden="true" />
        {t('switchAccount')}
      </a>
    </AuthShell>
  )
}
