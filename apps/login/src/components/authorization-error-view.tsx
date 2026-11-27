import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { buttonVariants } from '@identity/ui/components/button'
import { Link } from '@tanstack/react-router'
import { CircleAlert } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { translate, type Locale } from '#/lib/i18n'

export function AuthorizationErrorView({
  locale,
  error,
  errorDescription,
}: {
  locale: Locale
  error?: string
  errorDescription?: string
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('authorizationFailedTitle')}
      description={t('authorizationFailedDescription')}
    >
      <Alert variant="destructive">
        <CircleAlert aria-hidden="true" />
        <AlertTitle>
          <code className="break-all text-sm">
            {error ?? 'invalid_request'}
          </code>
        </AlertTitle>
        <AlertDescription>
          {errorDescription ?? t('oauthCallbackInvalid')}
        </AlertDescription>
      </Alert>
      <Link
        to="/"
        className={buttonVariants({ className: 'mt-6 w-full' })}
      >
        {t('authorizationRetry')}
      </Link>
    </AuthShell>
  )
}
