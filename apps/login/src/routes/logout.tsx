import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { createServerFn } from '@tanstack/react-start'

import { AuthShell } from '#/components/auth-shell'
import { beginAuthorization } from '#/lib/authorization-flow'
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
  const [starting, setStarting] = useState(false)

  // The browser may still remember other accounts. Signing in again after an
  // explicit sign-out lets the user choose one instead of silently continuing
  // as whichever account remains.
  async function signInAgain() {
    setStarting(true)
    try {
      window.location.assign(
        await beginAuthorization({
          data: { returnTo: '/account/profile', selectAccount: true },
        }),
      )
    } catch {
      setStarting(false)
    }
  }

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('signedOutTitle')}
      description={t('signedOutDescription')}
    >
      <button
        type="button"
        disabled={starting}
        onClick={() => void signInAgain()}
        className="mt-6 flex min-h-9 w-full items-center justify-center rounded-field bg-accent px-4 text-sm font-semibold text-accent-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
      >
        {t('signInAgain')}
      </button>
    </AuthShell>
  )
}
