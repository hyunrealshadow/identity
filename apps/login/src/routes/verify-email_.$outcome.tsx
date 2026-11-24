import { buttonVariants } from '@identity/ui/components/button'
import { createFileRoute, notFound } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Check } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

type Outcome = 'verified' | 'changed'

function outcome(value: string): Outcome | undefined {
  return value === 'verified' || value === 'changed' ? value : undefined
}

const loadOutcomePage = createServerFn({ method: 'GET' }).handler(() => ({
  locale: requestLocale(),
}))

/** Where the browser lands after a verification link was followed. */
export const Route = createFileRoute('/verify-email_/$outcome')({
  loader: async ({ params }) => {
    const result = outcome(params.outcome)
    if (!result) throw notFound()
    return { ...(await loadOutcomePage()), outcome: result }
  },
  component: VerifyEmailOutcomePage,
})

function VerifyEmailOutcomePage() {
  const { locale, outcome } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      compact
      title={t(outcome === 'changed' ? 'verifyEmailChangedTitle' : 'verifyEmailVerifiedTitle')}
      description={t(
        outcome === 'changed' ? 'verifyEmailChangedDescription' : 'verifyEmailVerifiedDescription',
      )}
      titleIcon={<Check className="size-6" aria-hidden="true" />}
    >
      <a className={buttonVariants({ className: 'w-full' })} href="/account/identifiers">
        {t('verifyEmailOpenAccount')}
      </a>
    </AuthShell>
  )
}
