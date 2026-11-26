import { MailCheck } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { translate, type Locale } from '#/lib/i18n'

export function VerifyEmailPageView({
  locale,
  token,
  error,
}: {
  locale: Locale
  token: string
  error?: string
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('verifyEmailTitle')}
      description={t(
        token ? 'verifyEmailDescription' : 'verifyEmailNoLinkDescription',
      )}
      titleIcon={<MailCheck className="size-6" aria-hidden="true" />}
    >
      {error ? (
        <ErrorAlert
          className="mb-5"
          title={t('verifyEmailFailed')}
          message={error}
        />
      ) : null}
      {token ? (
        <ProgressiveForm
          action="/verify-email"
          className="progressive-form"
          enhancementErrorMessage={t('enhancedNavigationError')}
        >
          <input type="hidden" name="token" value={token} />
          <SubmitButton fullWidth>{t('verifyEmailSubmit')}</SubmitButton>
        </ProgressiveForm>
      ) : null}
    </AuthShell>
  )
}
