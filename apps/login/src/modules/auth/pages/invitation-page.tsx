import { UserPlus } from 'lucide-react'

import { AccountAvatar } from '@identity/ui/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { translate, type Locale } from '#/lib/i18n'
import type { InvitationCheckResponse } from '#/lib/identity-types'

export interface InvitationPageData {
  locale: Locale
  uiLocales: string
  token: string
  account?: InvitationCheckResponse
  error?: string
  fields: Record<string, string>
  linkError?: string
}

export function InvitationPageView({ data }: { data: InvitationPageData }) {
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const account = data.account

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      title={t('invitationTitle')}
      description={t(
        account ? 'invitationDescription' : 'invitationNoLinkDescription',
      )}
      titleIcon={<UserPlus className="size-6" aria-hidden="true" />}
    >
      {data.linkError ? (
        <ErrorAlert
          className="mb-5"
          title={t('invitationLinkFailed')}
          message={data.linkError}
        />
      ) : data.error ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}
      {account ? (
        <>
          <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
            <AccountAvatar name={account.username} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold">
                {account.username}
              </p>
              <p className="truncate text-xs text-muted-foreground">
                {account.email}
              </p>
            </div>
          </div>
          <ProgressiveForm
            action="/invitation"
            className="progressive-form space-y-6"
            enhancementErrorMessage={t('enhancedNavigationError')}
            validationErrors={data.fields}
            noValidate
          >
            <input type="hidden" name="token" value={data.token} />
            <input type="hidden" name="ui_locales" value={data.uiLocales} />
            {/* Lets password managers save the new password for this account. */}
            <input
              type="hidden"
              name="username"
              value={account.username}
              autoComplete="username"
            />
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
            <SubmitButton fullWidth>{t('invitationSubmit')}</SubmitButton>
          </ProgressiveForm>
        </>
      ) : null}
    </AuthShell>
  )
}
