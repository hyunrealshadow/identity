import { CircleAlert, KeyRound } from 'lucide-react'

import { AccountAvatar } from '@identity/ui/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { translate, type Locale } from '#/lib/i18n'
import type { LoginStatusResponse } from '#/lib/identity-types'
import { LoginClient } from '#/modules/auth/components/login-client'
import { loginPasswordChangePath } from '#/modules/auth/lib/login-navigation'

export interface PasswordChangePageData {
  status?: LoginStatusResponse
  csrfToken: string
  loginId: string
  locale: Locale
  uiLocales: string
  error?: string
  fields: Record<string, string>
  restartRequired: boolean
  restartUnavailable: boolean
}

export function PasswordChangePageView({
  data,
}: {
  data: PasswordChangePageData
}) {
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
      title={
        restartRequired ? t('challengeExpiredTitle') : t('passwordChangeTitle')
      }
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

      {data.error && !restartRequired ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm
            action={loginPasswordChangePath}
            className="progressive-form"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
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
