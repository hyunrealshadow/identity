import { buttonVariants } from '@identity/ui/components/button'
import { ChevronRight, Plus } from 'lucide-react'
import { useState } from 'react'

import { AccountAvatar } from '@identity/ui/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import type {
  ActiveAccountsResponse,
  LoginClientDisplay,
} from '#/lib/identity-types'
import { translate, type Locale } from '#/lib/i18n'
import { LoginClient } from '#/modules/auth/components/login-client'
import { loginRegisterDestination } from '#/modules/auth/lib/login-navigation'

export interface LoginPageSearch {
  login_id?: string
  no_accounts?: string
  identifier?: string
  error?: string
  ui_locales?: string
}

export interface LoginPageData {
  accounts: ActiveAccountsResponse['accounts']
  csrfToken: string
  loginId: string
  locale: Locale
  uiLocales: string
  error?: string
  fieldError?: string
  formValues: Record<string, string | undefined>
  loginHint?: string
  challengeUri?: string
  client?: LoginClientDisplay
  registrationAvailable: boolean
}

export function LoginPageView({
  data,
  search,
}: {
  data: LoginPageData
  search: LoginPageSearch
}) {
  const [identifierError, setIdentifierError] = useState(data.fieldError)
  const loginId = data.loginId
  const showAccounts = data.accounts.length > 0 && search.no_accounts !== '1'
  const visibleError = search.error ?? data.error
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      title={showAccounts ? t('chooseAccount') : t('signIn')}
      description={
        showAccounts ? t('chooseAccountDescription') : t('signInDescription')
      }
    >
      <LoginClient client={data.client} locale={data.locale} />
      {visibleError ? (
        <ErrorAlert
          className="mb-5"
          message={visibleError}
          title={t('unableToContinue')}
        />
      ) : null}

      {showAccounts ? (
        <div className="auth-stagger-fast space-y-3">
          {data.accounts.map((account) => (
            <ProgressiveForm
              action="/login"
              key={account.id}
              className="progressive-form"
              enhancementErrorMessage={t('enhancedNavigationError')}
            >
              <input type="hidden" name="intent" value="select" />
              <input type="hidden" name="login_id" value={loginId} />
              <input type="hidden" name="session_id" value={account.id} />
              <input type="hidden" name="ui_locales" value={data.uiLocales} />
              <input
                type="hidden"
                name="csrf_token"
                value={data.csrfToken}
              />
              <SubmitButton
                variant="outline"
                fullWidth
                className="group h-auto justify-start gap-3 px-4 py-3 text-left whitespace-normal hover:-translate-y-0.5 hover:shadow-[0_14px_30px_-14px_rgba(0,0,0,0.3)]"
              >
                <AccountAvatar name={account.name} picture={account.picture} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold">
                    {account.name}
                  </span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {account.email}
                  </span>
                </span>
                <ChevronRight
                  className="size-4 text-muted-foreground transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-foreground"
                  aria-hidden="true"
                />
              </SubmitButton>
            </ProgressiveForm>
          ))}
          <a
            href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
            className={buttonVariants({
              variant: 'ghost',
              className: 'h-11 w-full font-semibold',
            })}
          >
            <Plus className="size-4" aria-hidden="true" />
            {t('useAnotherAccount')}
          </a>
        </div>
      ) : (
        <ProgressiveForm
          action="/login"
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="intent" value="identifier" />
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <TextField
            required
            name="identifier"
            label={t('identifier')}
            error={identifierError}
            autoFocus
            defaultValue={
              data.formValues.identifier ?? search.identifier ?? data.loginHint
            }
            autoComplete="username"
            placeholder="name@example.com"
            onChange={() => setIdentifierError(undefined)}
          />
          <SubmitButton fullWidth>{t('next')}</SubmitButton>
          {data.accounts.length > 0 ? (
            <a
              href={`/login?login_id=${encodeURIComponent(loginId)}${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
              className="auth-link mx-auto flex w-fit justify-center text-sm font-semibold text-primary"
            >
              {t('backToAccounts')}
            </a>
          ) : null}
        </ProgressiveForm>
      )}
      {!showAccounts && data.registrationAvailable ? (
        <p className="mt-6 text-center text-sm text-muted-foreground">
          {t('createAccountPrompt')}{' '}
          <a
            href={loginRegisterDestination(loginId, data.uiLocales || undefined)}
            className="text-link font-semibold text-foreground"
          >
            {t('createAccount')}
          </a>
        </p>
      ) : null}
    </AuthShell>
  )
}
