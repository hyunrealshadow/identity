import { ArrowLeft, CircleAlert, MailCheck } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { useSecondsUntil } from '#/components/use-seconds-until'
import { translate, type Locale } from '#/lib/i18n'
import type { LoginStatusResponse } from '#/lib/identity-types'
import { LoginClient } from '#/modules/auth/components/login-client'
import { loginRegisterPath } from '#/modules/auth/lib/login-navigation'

export interface RegisterPageData {
  status?: LoginStatusResponse
  csrfToken: string
  loginId: string
  locale: Locale
  uiLocales: string
  error?: string
  fields: Record<string, string>
  values: Record<string, string | undefined>
  linkEmail?: string
  linkError?: string
  restartRequired: boolean
  restartUnavailable: boolean
}

export function RegisterPageView({
  data,
  token,
}: {
  data: RegisterPageData
  token?: string
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const creating = Boolean(token) && Boolean(data.linkEmail)
  const resendAt = data.status?.registration_resend_available_at
  const sent = !creating && Boolean(resendAt)
  const resendWait = useSecondsUntil(resendAt)
  const available = data.status?.registration_available ?? false
  const { restartRequired, restartUnavailable } = data
  const signInPage = `/login?${new URLSearchParams({
    login_id: data.loginId,
    ...(data.uiLocales ? { ui_locales: data.uiLocales } : {}),
  })}`
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
        ) : undefined
      }
      title={
        restartRequired
          ? t('challengeExpiredTitle')
          : creating
            ? t('registrationDetailsTitle')
            : t('registrationTitle')
      }
      description={
        restartUnavailable
          ? t('authorizationRestartUnavailable')
          : restartRequired
            ? data.error || t('challengeExpiredDescription')
            : creating
              ? t('registrationDetailsDescription')
              : sent
                ? t('registrationSentDescription')
                : t('registrationDescription')
      }
    >
      <LoginClient client={data.status?.client} locale={data.locale} />

      {data.linkError && !restartRequired ? (
        <ErrorAlert
          className="mb-5"
          title={t('registrationLinkFailed')}
          message={data.linkError}
        />
      ) : data.error && !restartRequired ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm
            action={loginRegisterPath}
            className="progressive-form"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
            <input type="hidden" name="intent" value="restart" />
            {hidden}
            <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
          </ProgressiveForm>
        )
      ) : creating ? (
        <ProgressiveForm
          action={loginRegisterPath}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          validationErrors={data.fields}
          noValidate
        >
          {hidden}
          <input type="hidden" name="intent" value="register" />
          <input type="hidden" name="token" value={token} />
          <div className="space-y-1.5">
            <p className="text-sm font-medium">{t('accountEmail')}</p>
            <p className="truncate rounded-lg border bg-muted/50 px-3 py-2 text-sm">
              {data.linkEmail}
            </p>
          </div>
          <TextField
            required
            name="username"
            label={t('accountUsername')}
            error={data.fields.username}
            defaultValue={data.values.username}
            autoFocus
            autoComplete="username"
            description={t('registrationUsernameHint')}
          />
          <TextField
            required
            name="new_password"
            label={t('password')}
            error={data.fields.new_password}
            type="password"
            autoComplete="new-password"
            reveal={{ show: t('showPassword'), hide: t('hidePassword') }}
          />
          <TextField
            required
            name="confirm_password"
            label={t('installConfirmPassword')}
            error={data.fields.confirm_password}
            type="password"
            autoComplete="new-password"
          />
          <SubmitButton fullWidth>{t('registrationSubmit')}</SubmitButton>
        </ProgressiveForm>
      ) : available ? (
        <>
          {sent ? (
            <p
              className="mb-4 flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground"
              role="status"
            >
              <MailCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {t('registrationSentNotice')}
            </p>
          ) : null}
          <ProgressiveForm
            action={loginRegisterPath}
            className="progressive-form space-y-6"
            enhancementErrorMessage={t('enhancedNavigationError')}
            validationErrors={data.fields}
            noValidate
          >
            {hidden}
            <input type="hidden" name="intent" value="send" />
            <TextField
              required
              name="email"
              type="email"
              label={t('accountEmail')}
              error={data.fields.email}
              defaultValue={data.values.email}
              autoFocus={!sent}
              autoComplete="email"
              placeholder="name@example.com"
            />
            <SubmitButton
              variant={sent ? 'outline' : 'default'}
              fullWidth
              disabled={resendWait > 0}
            >
              {!sent
                ? t('registrationSend')
                : resendWait > 0
                  ? translate(data.locale, 'registrationResendIn', {
                      seconds: resendWait,
                    })
                  : t('registrationResend')}
            </SubmitButton>
          </ProgressiveForm>
        </>
      ) : data.status && !data.error && !data.linkError ? (
        <ErrorAlert className="mb-5" message={t('registrationUnavailable')} />
      ) : null}

      {!restartRequired && data.loginId ? (
        <a
          href={signInPage}
          className="text-link mx-auto mt-6 flex w-fit items-center gap-1.5 text-sm font-semibold"
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('registrationBack')}
        </a>
      ) : null}
    </AuthShell>
  )
}
