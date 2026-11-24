import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { MailCheck } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import {
  confirmEmailVerification,
  isFinalVerificationError,
} from '#/lib/email-verification.server'
import { errorMessage } from '#/lib/identity.server'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash, formErrorResponse, navigationResponse } from '#/lib/responses.server'

const PATH = '/verify-email'

interface VerifyEmailSearch {
  token?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadVerifyEmailPage = createServerFn({ method: 'GET' })
  .validator((data: { token: string }) => data)
  .handler(({ data }) => {
    const flash = consumeFormFlash(PATH)
    return {
      locale: requestLocale(),
      token: data.token,
      error: flash?.message,
    }
  })

/**
 * Where an emailed verification link lands. Opening the link only shows this
 * confirmation; the address is verified when the user continues, so a mail
 * scanner that fetches the link cannot use it. No account session is needed,
 * so the link also works on another device.
 */
export const Route = createFileRoute('/verify-email')({
  validateSearch: (search): VerifyEmailSearch => ({
    token: optionalString(search.token),
  }),
  loaderDeps: ({ search }) => ({ token: search.token ?? '' }),
  loader: ({ deps }) => loadVerifyEmailPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // The token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const locale = formLocale(request, null)
        const token = String(form.get('token') ?? '').trim()
        if (!token) {
          return formErrorResponse(
            request,
            PATH,
            translate(locale, 'verifyEmailMissingLink'),
            {},
          )
        }
        try {
          const result = await confirmEmailVerification(token, locale)
          return navigationResponse(request, `${PATH}/${result.changed ? 'changed' : 'verified'}`)
        } catch (error) {
          // A link that can never work is not offered again; a transient
          // failure keeps it so the user can retry.
          const destination = isFinalVerificationError(error)
            ? PATH
            : `${PATH}?token=${encodeURIComponent(token)}`
          return formErrorResponse(
            request,
            PATH,
            errorMessage(error, locale),
            {},
            undefined,
            destination,
          )
        }
      },
    },
  },
  component: VerifyEmailPage,
})

function VerifyEmailPage() {
  const { locale, token, error } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('verifyEmailTitle')}
      description={t(token ? 'verifyEmailDescription' : 'verifyEmailNoLinkDescription')}
      titleIcon={<MailCheck className="size-6" aria-hidden="true" />}
    >
      {error ? <ErrorAlert className="mb-5" title={t('verifyEmailFailed')} message={error} /> : null}
      {token ? (
        <ProgressiveForm
          action={PATH}
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
