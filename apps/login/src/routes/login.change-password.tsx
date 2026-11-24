import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { CircleAlert, KeyRound } from 'lucide-react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type { ActiveAccountsResponse, LoginStatusResponse } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import {
  loginChallengeDestination,
  loginPasswordChangePath,
} from '#/lib/login-navigation'
import { submitPasswordChange } from '#/lib/password-change.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'

interface PasswordChangeSearch {
  login_id?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadPasswordChangePage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; restart?: string; uiLocales?: string }) => data)
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
      restartRequired: data.restart === 'required' || data.restart === 'unavailable',
      restartUnavailable: data.restart === 'unavailable',
      redirectTo: undefined as string | undefined,
    }
    if (!loginId) return { ...page, error: page.error ?? translate(locale, 'missingLogin') }
    try {
      page.csrfToken = (await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')).csrf_token
      if (page.restartRequired) {
        return {
          ...page,
          error: page.error ?? translate(locale, page.restartUnavailable ? 'authorizationRestartUnavailable' : 'challengeExpiredDescription'),
        }
      }
      page.status = await identityJson<LoginStatusResponse>(`/api/auth/login/${encodeURIComponent(loginId)}`)
      if (page.status.status === 'expired') {
        return { ...page, restartRequired: true, error: translate(locale, 'challengeExpiredDescription') }
      }
      if (page.status.status !== 'password_change_required') {
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            page.status.continue_uri ??
            page.status.challenge_uri ??
            ((page.status.status === 'mfa_required' || page.status.status === 'identifier_verified') &&
            page.status.preferred_credential_type
              ? loginChallengeDestination(loginId, page.status.preferred_credential_type, uiLocales)
              : `/login?${search}`),
        }
      }
      return page
    } catch (error) {
      if (isTerminalLoginError(error)) {
        return { ...page, restartRequired: true, error: page.error ?? translate(locale, 'challengeExpiredDescription') }
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
      throw redirect({ href: withUiLocales(page.redirectTo, page.uiLocales), reloadDocument: true })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitPasswordChange(request),
    },
  },
  component: PasswordChangePage,
})

function PasswordChangePage() {
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const user = data.status?.user
  const { restartRequired, restartUnavailable } = data
  const hidden = (
    <>
      <input type="hidden" name="login_id" value={data.loginId} />
      <input type="hidden" name="csrf_token" value={data.csrfToken} />
      <input type="hidden" name="ui_locales" value={data.uiLocales} />
    </>
  )

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      tone={restartRequired ? 'danger' : 'default'}
      titleIcon={
        restartRequired ? (
          <CircleAlert className="size-6" aria-hidden="true" />
        ) : (
          <KeyRound className="size-6" aria-hidden="true" />
        )
      }
      title={restartRequired ? t('challengeExpiredTitle') : t('passwordChangeTitle')}
      description={
        restartUnavailable
          ? t('authorizationRestartUnavailable')
          : restartRequired
            ? data.error || t('challengeExpiredDescription')
            : t('passwordChangeDescription')
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

      {data.error && !restartRequired ? <ErrorAlert className="mb-5" message={data.error} /> : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm action={loginPasswordChangePath} className="progressive-form" enhancementErrorMessage={t('enhancedNavigationError')}>
            <input type="hidden" name="intent" value="restart" />
            {hidden}
            <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
          </ProgressiveForm>
        )
      ) : (
        <ProgressiveForm
          action={loginPasswordChangePath}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          noValidate
        >
          {hidden}
          <TextField
            required
            name="new_password"
            label={t('accountNewPassword')}
            error={data.fields.new_password}
            autoFocus
            type="password"
            autoComplete="new-password"
            reveal={{ show: t('showPassword'), hide: t('hidePassword') }}
          />
          <TextField
            required
            name="confirm_password"
            label={t('accountConfirmPassword')}
            error={data.fields.confirm_password}
            type="password"
            autoComplete="new-password"
          />
          <SubmitButton fullWidth>{t('passwordChangeSubmit')}</SubmitButton>
        </ProgressiveForm>
      )}
    </AuthShell>
  )
}
