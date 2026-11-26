import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

interface SignedOutSearch {
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadSignedOutPage = createServerFn({ method: 'GET' })
  .validator((data: { uiLocales?: string }) => data)
  .handler(({ data }) => ({
    locale: requestLocale(data.uiLocales?.split(' ')),
  }))

/**
 * The provider returns the browser here after RP-Initiated Logout via the
 * client's registered post_logout_redirect_uri. It must render without an
 * account session, so it deliberately avoids the account loader.
 */
export const Route = createFileRoute('/logout')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { startSignIn } = await import('#/lib/oauth.server')
        const destination = (
          await startSignIn('/account/profile', { selectAccount: true })
        ).toString()
        if (request.headers.get('x-enhanced-form') === '1') {
          return Response.json({ redirect: destination })
        }
        return new Response(null, {
          status: 303,
          headers: { location: destination },
        })
      },
    },
  },
  validateSearch: (search): SignedOutSearch => ({
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({ uiLocales: search.ui_locales }),
  loader: ({ deps }) => loadSignedOutPage({ data: deps }),
  component: SignedOutPage,
})

function SignedOutPage() {
  const { locale } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('signedOutTitle')}
      description={t('signedOutDescription')}
    >
      {/* The browser may still remember other accounts. Signing in again after
          an explicit sign-out lets the user choose one instead of silently
          continuing as whichever account remains. */}
      <ProgressiveForm
        action="/logout"
        enhancementErrorMessage={t('temporaryError')}
      >
        <SubmitButton className="mt-6 w-full">{t('signInAgain')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
