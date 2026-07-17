import {
  Alert,
  Avatar,
  Button,
  Input,
  Label,
  TextField,
} from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, Eye, EyeOff, KeyRound } from 'lucide-react'
import { useState } from 'react'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import {
  errorMessage,
  identityJson,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  ChallengeResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import {
  formErrorResponse,
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
  .validator((data: { loginId: string }) => data)
  .handler(async ({ data }) => {
    try {
      const [active, status] = await Promise.all([
        identityJson<ActiveAccountsResponse>('/api/auth/sessions/active'),
        identityJson<LoginStatusResponse>(
          `/api/auth/login/${encodeURIComponent(data.loginId)}`,
        ),
      ])
      return {
        status,
        csrfToken: active.csrf_token,
        locale: requestLocale(status.ui_locales),
        uiLocales: status.ui_locales?.join(' ') ?? '',
        error: undefined,
      }
    } catch (error) {
      const locale = requestLocale()
      return {
        status: undefined,
        csrfToken: '',
        locale,
        uiLocales: '',
        error: errorMessage(error, locale),
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
  loaderDeps: ({ search }) => ({ loginId: search.login_id ?? '' }),
  loader: ({ deps }) =>
    deps.loginId
      ? loadChallengePage({ data: { loginId: deps.loginId } })
      : Promise.resolve({
        status: undefined,
        csrfToken: '',
        locale: 'en-US' as const,
        uiLocales: '',
        error: translate('en-US', 'missingLogin'),
        }),
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

          const continueUri =
            result.continue_uri ??
            `/oauth2/continue?login_id=${encodeURIComponent(loginId)}`
          return navigationResponse(request, continueUri)
        } catch (error) {
          return formErrorResponse(
            request,
            '/login/challenge',
            errorMessage(error, locale),
            { login_id: loginId, credential_type: credentialType, ui_locales: uiLocales },
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
  const loginId = search.login_id ?? ''
  const credentialType = search.credential_type === 'otp' ? 'otp' : 'password'
  const isOtp = credentialType === 'otp'
  const visibleError = search.error ?? data.error
  const user = data.status?.user
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)

  return (
    <AuthShell
      lang={data.locale}
      title={isOtp ? t('otpTitle') : t('passwordTitle')}
      description={
        isOtp
          ? t('otpDescription')
          : t('passwordDescription')
      }
    >
      {user ? (
        <div className="mb-6 flex items-center gap-3 rounded-2xl border border-divider bg-surface-secondary p-3">
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
        <Alert status="danger" className="mb-5">
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

        {isOtp ? (
          <TextField isRequired fullWidth name="credential">
            <Label>{t('otp')}</Label>
            <Input
              autoFocus
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              pattern="[0-9]*"
              placeholder="000000"
              className="text-center font-mono text-xl tracking-[0.35em]"
            />
          </TextField>
        ) : (
          <TextField isRequired fullWidth name="credential">
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
          </TextField>
        )}

        <Button type="submit" fullWidth>
          {isOtp ? t('verify') : t('login')}
        </Button>
      </ProgressiveForm>

      <a
        href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
        className="mt-5 flex items-center justify-center gap-1.5 text-sm font-semibold text-accent hover:underline"
      >
        <ArrowLeft className="size-4" aria-hidden="true" />
        {t('switchAccount')}
      </a>
      <p className="mt-7 flex items-center justify-center gap-2 text-xs text-muted">
        <KeyRound className="size-3.5" aria-hidden="true" />
        {t('encrypted')}
      </p>
    </AuthShell>
  )
}
