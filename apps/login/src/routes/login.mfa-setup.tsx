import { buttonVariants } from '@identity/ui/components/button'
import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@identity/ui/components/input-group'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, Check, ChevronDown, CircleAlert, Copy, ExternalLink } from 'lucide-react'
import { useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { ProgressiveForm } from '#/components/progressive-form'
import { RecoveryCodeList, RecoveryCodeTools } from '#/components/recovery-code-tools'
import { SubmitButton } from '#/components/submit-button'
import { TotpInput } from '#/components/totp-input'
import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
  MfaEnrollmentResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { submitLoginMfaSetup } from '#/lib/login-mfa-setup.server'
import {
  loginChallengeDestination,
  loginMfaSetupPath,
} from '#/lib/login-navigation'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'

interface MfaSetupSearch {
  login_id?: string
  restart?: string
  recovery_saved?: string
  step?: 'verify'
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

async function qrCodeSvg(uri: string) {
  try {
    const { default: QRCode } = await import('qrcode')
    return await QRCode.toString(uri, {
      type: 'svg',
      margin: 0,
      errorCorrectionLevel: 'M',
      color: { dark: '#18181b', light: '#ffffff' },
    })
  } catch {
    // The setup key and authenticator link remain available.
    return undefined
  }
}

const loadMfaSetupPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; restart?: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginMfaSetupPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const codeError = flash?.fields?.code ?? (flash?.field === 'code' ? flash.message : undefined)
    const page = {
      loginId,
      locale,
      uiLocales,
      csrfToken: '',
      status: undefined as LoginStatusResponse | undefined,
      enrollment: undefined as MfaEnrollmentResponse | undefined,
      qrCode: undefined as string | undefined,
      error: codeError ? undefined : flash?.message,
      codeError,
      restartRequired: false,
      restartUnavailable: false,
      redirectTo: undefined as string | undefined,
    }
    if (!loginId) return { ...page, error: page.error ?? translate(locale, 'missingLogin') }

    try {
      const active = await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')
      page.csrfToken = active.csrf_token
      if (data.restart === 'required' || data.restart === 'unavailable') {
        const restartUnavailable = data.restart === 'unavailable'
        return {
          ...page,
          restartRequired: true,
          restartUnavailable,
          error:
            page.error ??
            translate(
              locale,
              restartUnavailable ? 'authorizationRestartUnavailable' : 'challengeExpiredDescription',
            ),
        }
      }
      const status = await identityJson<LoginStatusResponse>(
        `/api/auth/login/${encodeURIComponent(loginId)}`,
      )
      page.status = status
      if (status.status === 'expired') {
        return { ...page, restartRequired: true, error: translate(locale, 'challengeExpiredDescription') }
      }
      if (status.status !== 'mfa_enrollment_required') {
        // The interaction moved on (completed elsewhere, or a factor was
        // enrolled meanwhile): continue wherever it now stands.
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            status.continue_uri ??
            (status.status === 'mfa_required' && status.preferred_credential_type
              ? loginChallengeDestination(loginId, status.preferred_credential_type, uiLocales)
              : `/login?${search}`),
        }
      }
      const enrollment = await identityJson<MfaEnrollmentResponse>('/api/auth/login/mfa-enrollment', {
        method: 'POST',
        csrfToken: active.csrf_token,
        body: { id: loginId },
      })
      return { ...page, enrollment, qrCode: await qrCodeSvg(enrollment.otp_auth_uri) }
    } catch (error) {
      if (isTerminalLoginError(error)) {
        return {
          ...page,
          restartRequired: true,
          error: page.error ?? translate(locale, 'challengeExpiredDescription'),
        }
      }
      return { ...page, error: page.error ?? errorMessage(error, locale) }
    }
  })

export const Route = createFileRoute('/login/mfa-setup')({
  validateSearch: (search): MfaSetupSearch => ({
    login_id: optionalString(search.login_id),
    restart: optionalString(search.restart),
    // Which pending enrollment's recovery codes were saved; a plain query
    // parameter so moving on to the authenticator works without JavaScript.
    recovery_saved: optionalString(search.recovery_saved),
    step: search.step === 'verify' ? 'verify' : undefined,
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps }) => {
    const page = await loadMfaSetupPage({ data: deps })
    if (page.redirectTo) {
      throw redirect({ href: withUiLocales(page.redirectTo, deps.uiLocales), reloadDocument: true })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitLoginMfaSetup(request),
    },
  },
  component: MfaSetupPage,
})

function MfaSetupPage() {
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const [codeError, setCodeError] = useState(data.codeError)
  const [secretCopied, setSecretCopied] = useState(false)
  const user = data.status?.user
  const enrollment = data.enrollment
  const search = Route.useSearch()
  const recoverySaved = search.recovery_saved
  const hasRecoveryCodes = (enrollment?.recovery_codes.length ?? 0) > 0
  // Three screens, like the account center: recovery codes, authenticator,
  // verification. The codes belong to one pending enrollment: if it expired
  // and a new one was issued, its new codes are shown again.
  const screen: 'recovery' | 'scan' | 'verify' =
    hasRecoveryCodes && recoverySaved !== enrollment?.expires_at
      ? 'recovery'
      : search.step === 'verify' || data.codeError
        ? 'verify'
        : 'scan'
  const screenSearch = (next: 'recovery' | 'scan' | 'verify') => ({
    login_id: data.loginId,
    ui_locales: data.uiLocales || undefined,
    recovery_saved: next === 'recovery' ? undefined : (hasRecoveryCodes ? enrollment?.expires_at : undefined),
    step: next === 'verify' ? ('verify' as const) : undefined,
  })
  const pathname = loginMfaSetupPath
  const canSwitchAccount = !data.status?.requires_reauthentication

  async function copySecret() {
    if (!enrollment) return
    try {
      await navigator.clipboard.writeText(enrollment.secret)
      setSecretCopied(true)
      window.setTimeout(() => setSecretCopied(false), 2000)
    } catch {
      // The setup key remains selectable when clipboard access is unavailable.
    }
  }

  const hiddenFields = (
    <>
      <input type="hidden" name="login_id" value={data.loginId} />
      <input type="hidden" name="csrf_token" value={data.csrfToken} />
      <input type="hidden" name="ui_locales" value={data.uiLocales} />
      {recoverySaved ? <input type="hidden" name="recovery_saved" value={recoverySaved} /> : null}
    </>
  )

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      tone={data.restartRequired ? 'danger' : 'default'}
      titleIcon={data.restartRequired ? <CircleAlert className="size-6" aria-hidden="true" /> : undefined}
      title={
        data.restartRequired
          ? t('challengeExpiredTitle')
          : !enrollment || screen === 'scan'
            ? t('mfaSetupTitle')
            : screen === 'recovery'
              ? t('accountRecoveryCodesTitle')
              : t('otpTitle')
      }
      description={
        data.restartUnavailable
          ? t('authorizationRestartUnavailable')
          : data.restartRequired
            ? data.error || t('challengeExpiredDescription')
            : !enrollment || screen === 'scan'
              ? t('mfaSetupDescription')
              : screen === 'recovery'
                ? t('mfaSetupRecoveryDescription')
                : t('accountMfaStepVerifyDescription')
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

      {data.error && !data.restartRequired ? (
        <ErrorAlert className="mb-5" title={t('verificationFailed')} message={data.error} />
      ) : null}

      {data.restartRequired && !data.restartUnavailable ? (
        <ProgressiveForm action={pathname} enhancementErrorMessage={t('enhancedNavigationError')}>
          <input type="hidden" name="intent" value="restart" />
          {hiddenFields}
          <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
        </ProgressiveForm>
      ) : null}

      {!data.restartRequired && enrollment && screen === 'recovery' ? (
        <>
          <RecoveryCodeList
            codes={enrollment.recovery_codes}
            copyLabel={t('accountRecoveryCodeCopy')}
            copiedLabel={t('accountRecoveryCodeCopied')}
          />
          <div className="js-only mt-3 flex flex-wrap gap-2">
            <RecoveryCodeTools
              codes={enrollment.recovery_codes}
              copyLabel={t('accountRecoveryCodesCopy')}
              copiedLabel={t('accountRecoveryCodesCopied')}
              printLabel={t('accountRecoveryCodesPrint')}
              downloadLabel={t('accountRecoveryCodesDownload')}
            />
          </div>
          <Link
            to="/login/mfa-setup"
            search={{ ...screenSearch('scan'), recovery_saved: enrollment.expires_at }}
            className={buttonVariants({ className: 'mt-6 w-full' })}
          >
            {t('mfaSetupRecoveryContinue')}
          </Link>
        </>
      ) : null}

      {!data.restartRequired && enrollment && screen === 'scan' ? (
        <>
          {data.qrCode ? (
            <div
              className="account-qr mx-auto"
              role="img"
              aria-label={t('accountMfaUseQrCode')}
              dangerouslySetInnerHTML={{ __html: data.qrCode }}
            />
          ) : null}
          <details className="auth-methods group mt-3" open={!data.qrCode}>
            <summary className="mx-auto flex min-h-9 w-fit cursor-pointer list-none items-center gap-1 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
              {t('accountMfaManualEntry')}
              <ChevronDown className="size-4 transition-transform group-open:rotate-180" aria-hidden="true" />
            </summary>
            <div className="mt-2 grid gap-2 pb-1">
              <Field>
                <FieldLabel htmlFor="mfa-setup-key">{t('accountMfaSecret')}</FieldLabel>
                <InputGroup className="bg-muted/50">
                  <InputGroupInput id="mfa-setup-key" value={enrollment.secret} readOnly className="font-mono" />
                  <InputGroupAddon align="inline-end" className="js-only">
                    <InputGroupButton
                      size="icon-xs"
                      aria-label={secretCopied ? t('accountMfaSecretCopied') : t('accountMfaSecretCopy')}
                      onClick={() => void copySecret()}
                    >
                      {secretCopied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                    </InputGroupButton>
                  </InputGroupAddon>
                </InputGroup>
              </Field>
              <a
                href={enrollment.otp_auth_uri}
                className={buttonVariants({ variant: 'link', className: 'h-auto w-fit px-0 has-[>svg]:px-0' })}
              >
                {t('accountMfaOpenAuthenticator')}
                <ExternalLink aria-hidden="true" />
              </a>
            </div>
          </details>

          <Link
            to="/login/mfa-setup"
            search={screenSearch('verify')}
            className={buttonVariants({ className: 'mt-6 w-full' })}
          >
            {t('accountMfaContinue')}
          </Link>
          {hasRecoveryCodes ? (
            <Link
              to="/login/mfa-setup"
              search={screenSearch('recovery')}
              className={buttonVariants({ variant: 'link', size: 'sm', className: 'mx-auto mt-3 flex w-fit text-muted-foreground' })}
            >
              {t('mfaSetupBackToRecovery')}
            </Link>
          ) : null}
        </>
      ) : null}

      {!data.restartRequired && enrollment && screen === 'verify' ? (
        <>
          <ProgressiveForm
            action={pathname}
            className="progressive-form space-y-6"
            enhancementErrorMessage={t('enhancedNavigationError')}
            noValidate
          >
            {hiddenFields}
            <Field data-invalid={codeError ? true : undefined}>
              <FieldLabel htmlFor="mfa-setup-code">{t('otp')}</FieldLabel>
              <TotpInput
                id="mfa-setup-code"
                name="code"
                type="text"
                required
                autoFocus
                isInvalid={Boolean(codeError)}
                aria-invalid={Boolean(codeError)}
                aria-describedby={codeError ? 'mfa-setup-code-error' : undefined}
                onChange={() => setCodeError(undefined)}
              />
              {codeError ? <FieldError id="mfa-setup-code-error">{codeError}</FieldError> : null}
            </Field>
            <SubmitButton fullWidth>{t('mfaSetupConfirm')}</SubmitButton>
          </ProgressiveForm>

          {data.codeError && enrollment.algorithm !== 'SHA1' ? (
            <ProgressiveForm
              action={pathname}
              className="mt-4 text-center text-sm text-muted-foreground"
              enhancementErrorMessage={t('enhancedNavigationError')}
            >
              <input type="hidden" name="intent" value="legacy" />
              {hiddenFields}
              {t('mfaSetupLegacyHint')}
              <SubmitButton variant="link" size="sm" className="h-auto px-1 font-medium">
                {t('accountMfaUseLegacy')}
              </SubmitButton>
            </ProgressiveForm>
          ) : null}
          <Link
            to="/login/mfa-setup"
            search={screenSearch('scan')}
            className={buttonVariants({ variant: 'link', size: 'sm', className: 'mx-auto mt-3 flex w-fit text-muted-foreground' })}
          >
            {t('mfaSetupBackToScan')}
          </Link>
        </>
      ) : null}

      {!data.restartRequired && canSwitchAccount && data.loginId ? (
        <ProgressiveForm action={pathname} className="mt-6" enhancementErrorMessage={t('enhancedNavigationError')}>
          {hiddenFields}
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
