import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, CircleAlert, MailCheck } from 'lucide-react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { useSecondsUntil } from '#/components/use-seconds-until'
import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
  PasswordResetStatusResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { loginChallengeDestination, loginPasswordResetPath } from '#/lib/login-navigation'
import { submitPasswordReset } from '#/lib/password-reset.server'
import { consumeFormFlash } from '#/lib/responses.server'

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
  .validator((data: { loginId: string; token?: string; restart?: string; uiLocales?: string }) => data)
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
      restartRequired: data.restart === 'required' || data.restart === 'unavailable',
      restartUnavailable: data.restart === 'unavailable',
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
      if (data.token && !flash) {
        try {
          await identityJson<PasswordResetStatusResponse>('/api/auth/login/password-reset/check', {
            method: 'POST',
            csrfToken: page.csrfToken,
            body: { id: loginId, token: data.token },
          })
        } catch (error) {
          if (isTerminalLoginError(error)) throw error
          page.linkError = errorMessage(error, locale)
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
  component: PasswordResetPage,
})

function PasswordResetPage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const token = search.token
  const settingPassword = Boolean(token) && !data.linkError
  const resendAt = data.status?.password_reset_resend_available_at
  const sent = !token && Boolean(resendAt)
  const resendWait = useSecondsUntil(resendAt)
  const user = data.status?.user
  const identifier = data.status?.identifier
  const { restartRequired, restartUnavailable } = data
  const passwordPage = loginChallengeDestination(data.loginId, 'password', data.uiLocales || undefined)
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
      titleIcon={restartRequired ? <CircleAlert className="size-6" aria-hidden="true" /> : undefined}
      title={
        restartRequired
          ? t('challengeExpiredTitle')
          : settingPassword
            ? t('passwordResetNewTitle')
            : t('passwordResetTitle')
      }
      description={
        restartUnavailable
          ? t('authorizationRestartUnavailable')
          : restartRequired
            ? data.error || t('challengeExpiredDescription')
            : settingPassword
              ? t('passwordResetNewDescription')
              : sent
                ? t('passwordResetSentDescription')
                : t('passwordResetDescription')
      }
    >
      <LoginClient client={data.status?.client} locale={data.locale} />
      {user || identifier ? (
        <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
          <AccountAvatar name={user?.name ?? identifier!} picture={user?.picture} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{user?.name ?? identifier}</p>
            {user ? <p className="truncate text-xs text-muted-foreground">{user.email}</p> : null}
          </div>
        </div>
      ) : null}

      {data.linkError && !restartRequired ? (
        <ErrorAlert className="mb-5" title={t('passwordResetLinkFailed')} message={data.linkError} />
      ) : data.error && !restartRequired ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm action={loginPasswordResetPath} className="progressive-form" enhancementErrorMessage={t('enhancedNavigationError')}>
            <input type="hidden" name="intent" value="restart" />
            {hidden}
            <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
          </ProgressiveForm>
        )
      ) : settingPassword ? (
        <ProgressiveForm
          action={loginPasswordResetPath}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          noValidate
        >
          {hidden}
          <input type="hidden" name="intent" value="reset" />
          <input type="hidden" name="token" value={token} />
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
          <SubmitButton fullWidth>{t('passwordResetSubmit')}</SubmitButton>
        </ProgressiveForm>
      ) : data.status?.password_reset_available ? (
        <>
          {sent ? (
            <p className="mb-4 flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground" role="status">
              <MailCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {t('passwordResetSentNotice')}
            </p>
          ) : null}
          <ProgressiveForm action={loginPasswordResetPath} className="progressive-form" enhancementErrorMessage={t('enhancedNavigationError')}>
            {hidden}
            <SubmitButton
              name="intent"
              value="send"
              variant={sent ? 'outline' : 'default'}
              fullWidth
              autoFocus={!sent}
              disabled={resendWait > 0}
            >
              {!sent
                ? t('passwordResetSend')
                : resendWait > 0
                  ? translate(data.locale, 'emailCodeResendIn', { seconds: resendWait })
                  : t('passwordResetResend')}
            </SubmitButton>
          </ProgressiveForm>
        </>
      ) : null}

      {!restartRequired && data.loginId ? (
        <a
          href={passwordPage}
          className="text-link mx-auto mt-6 flex w-fit items-center gap-1.5 text-sm font-semibold"
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('passwordResetBack')}
        </a>
      ) : null}
    </AuthShell>
  )
}
