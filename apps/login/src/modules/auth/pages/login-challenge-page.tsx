import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { ArrowLeft, CircleAlert, CircleCheck, MailCheck } from 'lucide-react'
import { useState } from 'react'

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
import { LoginMethodAlternatives } from '#/modules/auth/components/login-method-alternatives'
import {
  loginMethodPath,
  loginPasswordResetDestination,
  type LoginCredentialType,
} from '#/modules/auth/lib/login-navigation'
import { GroupedCodeInput, TotpInput } from '#/modules/mfa/components/totp-input'
import { PasskeyLogin } from '#/modules/passkey/components/passkey-login'

export interface ChallengeSearch {
  login_id?: string
  /** The token of an emailed sign-in link. */
  token?: string
  error?: string
  restart?: string
  /** `password_reset` after a forgotten password was replaced. */
  notice?: string
  ui_locales?: string
}

export interface ChallengePageData {
  status?: LoginStatusResponse
  csrfToken: string
  loginId: string
  locale: Locale
  uiLocales: string
  error?: string
  fieldError?: string
  restartRequired: boolean
  restartUnavailable: boolean
}

export function ChallengePageView({
  data,
  search,
  credentialType,
}: {
  data: ChallengePageData
  search: ChallengeSearch
  credentialType: LoginCredentialType
}) {
  const [credentialError, setCredentialError] = useState(data.fieldError)
  const loginId = data.loginId
  const pathname = loginMethodPath(credentialType)
  const isPasskey = credentialType === 'passkey'
  const isOtp = credentialType === 'otp'
  const isRecoveryCode = credentialType === 'recovery_code'
  const isEmail = credentialType === 'email_otp'
  const emailLinkToken = isEmail ? search.token : undefined
  const emailResendAt = data.status?.email_code_resend_available_at
  const emailSent = isEmail && Boolean(emailResendAt)
  const emailResendWait = useSecondsUntil(emailResendAt)
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const canSwitchAccount = !data.status?.requires_reauthentication
  const visibleError = search.error ?? data.error
  const user = data.status?.user
  const identifier = data.status?.identifier
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
      titleIcon={
        restartRequired ? (
          <CircleAlert className="size-6" aria-hidden="true" />
        ) : undefined
      }
      title={
        restartRequired
          ? t('challengeExpiredTitle')
          : isPasskey
            ? t('usePasskey')
            : isRecoveryCode
              ? t('recoveryCodeTitle')
              : emailLinkToken
                ? t('emailLinkTitle')
                : isEmail
                  ? t('emailCodeTitle')
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
                : emailLinkToken
                  ? t('emailLinkDescription')
                  : isEmail
                    ? t(emailSent ? 'emailCodeSentDescription' : 'emailCodeDescription')
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
      ) : identifier ? (
        <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
          <AccountAvatar name={identifier} />
          <p className="min-w-0 flex-1 truncate text-sm font-semibold">
            {identifier}
          </p>
        </div>
      ) : null}

      {visibleError && !restartRequired ? (
        <ErrorAlert
          className="mb-5"
          title={t('verificationFailed')}
          message={visibleError}
        />
      ) : (search.notice === 'password_reset' ||
          search.notice === 'registered') &&
        !restartRequired &&
        credentialType === 'password' ? (
        <p
          className="mb-5 flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground"
          role="status"
        >
          <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          {t(search.notice === 'registered' ? 'registrationDone' : 'passwordResetDone')}
        </p>
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
      ) : !restartRequired && emailLinkToken ? (
        <ProgressiveForm
          action={pathname}
          className="progressive-form"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <input type="hidden" name="credential" value={emailLinkToken} />
          <SubmitButton fullWidth autoFocus>
            {t('emailLinkContinue')}
          </SubmitButton>
        </ProgressiveForm>
      ) : !restartRequired && isEmail && !emailSent ? (
        <ProgressiveForm
          action={pathname}
          className="progressive-form"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <SubmitButton fullWidth name="intent" value="send" autoFocus>
            {t('emailCodeSend')}
          </SubmitButton>
        </ProgressiveForm>
      ) : !restartRequired && !isPasskey ? (
        <ProgressiveForm
          action={pathname}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          noValidate
        >
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />

          {isEmail ? (
            <p
              className="flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground"
              role="status"
            >
              <MailCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {t('emailCodeSentNotice')}
            </p>
          ) : null}

          {isOtp || isEmail ? (
            <Field data-invalid={credentialError ? true : undefined}>
              <FieldLabel htmlFor="login-otp">
                {isEmail ? t('emailCode') : t('otp')}
              </FieldLabel>
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
              <FieldLabel htmlFor="login-recovery-code">
                {t('recoveryCode')}
              </FieldLabel>
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
                <FieldError id="login-recovery-code-error">
                  {credentialError}
                </FieldError>
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

          {credentialType === 'password' && data.status?.password_reset_available ? (
            <p className="-mt-3 text-right text-sm">
              <a
                href={loginPasswordResetDestination(
                  loginId,
                  data.uiLocales || undefined,
                )}
                className="text-link font-medium"
              >
                {t('forgotPassword')}
              </a>
            </p>
          ) : null}

          <SubmitButton fullWidth>
            {isOtp || isRecoveryCode || isEmail ? t('verify') : t('login')}
          </SubmitButton>
        </ProgressiveForm>
      ) : null}

      {!restartRequired && emailSent && !emailLinkToken ? (
        <ProgressiveForm
          action={pathname}
          className="mt-4"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <SubmitButton
            name="intent"
            value="send"
            variant="outline"
            fullWidth
            disabled={emailResendWait > 0}
          >
            {emailResendWait > 0
              ? translate(data.locale, 'emailCodeResendIn', {
                  seconds: emailResendWait,
                })
              : t('emailCodeResend')}
          </SubmitButton>
        </ProgressiveForm>
      ) : null}

      {!restartRequired &&
      isPasskey &&
      (data.status?.status === 'identifier_verified' ||
        data.status?.status === 'mfa_required') &&
      data.status.credential_types.includes('passkey') ? (
        <PasskeyLogin
          loginId={loginId}
          csrfToken={data.csrfToken}
          locale={data.locale}
          uiLocales={data.uiLocales}
          primary
        />
      ) : null}

      {!restartRequired ? (
        <LoginMethodAlternatives
          currentMethod={credentialType}
          status={data.status}
          loginId={loginId}
          uiLocales={data.uiLocales}
          locale={data.locale}
        />
      ) : null}

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
