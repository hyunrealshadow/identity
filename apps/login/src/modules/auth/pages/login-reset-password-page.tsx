import { ArrowLeft, CircleAlert, MailCheck } from 'lucide-react'

import { AccountAvatar } from '@identity/ui/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { useSecondsUntil } from '#/components/use-seconds-until'
import { translate, type Locale } from '#/lib/i18n'
import type { LoginStatusResponse } from '#/lib/identity-types'
import { LoginClient } from '#/modules/auth/components/login-client'
import {
  loginChallengeDestination,
  loginPasswordResetPath,
} from '#/modules/auth/lib/login-navigation'

export interface PasswordResetPageData {
  status?: LoginStatusResponse
  csrfToken: string
  loginId: string
  locale: Locale
  uiLocales: string
  error?: string
  fields: Record<string, string>
  linkError?: string
  restartRequired: boolean
  restartUnavailable: boolean
}

export function PasswordResetPageView({
  data,
  token,
}: {
  data: PasswordResetPageData
  token?: string
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const settingPassword = Boolean(token) && !data.linkError
  const resendAt = data.status?.password_reset_resend_available_at
  const sent = !token && Boolean(resendAt)
  const resendWait = useSecondsUntil(resendAt)
  const user = data.status?.user
  const identifier = data.status?.identifier
  const { restartRequired, restartUnavailable } = data
  const passwordPage = loginChallengeDestination(
    data.loginId,
    'password',
    data.uiLocales || undefined,
  )
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
          <AccountAvatar
            name={user?.name ?? identifier!}
            picture={user?.picture}
          />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">
              {user?.name ?? identifier}
            </p>
            {user ? (
              <p className="truncate text-xs text-muted-foreground">
                {user.email}
              </p>
            ) : null}
          </div>
        </div>
      ) : null}

      {data.linkError && !restartRequired ? (
        <ErrorAlert
          className="mb-5"
          title={t('passwordResetLinkFailed')}
          message={data.linkError}
        />
      ) : data.error && !restartRequired ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm
            action={loginPasswordResetPath}
            className="progressive-form"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
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
            <p
              className="mb-4 flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground"
              role="status"
            >
              <MailCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {t('passwordResetSentNotice')}
            </p>
          ) : null}
          <ProgressiveForm
            action={loginPasswordResetPath}
            className="progressive-form"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
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
                  ? translate(data.locale, 'emailCodeResendIn', {
                      seconds: resendWait,
                    })
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
