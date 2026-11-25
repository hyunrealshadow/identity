import { buttonVariants } from '@identity/ui/components/button'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Check } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

const loadAcceptedPage = createServerFn({ method: 'GET' }).handler(() => ({
  locale: requestLocale(),
}))

/** Where the browser lands after an invitation was accepted. */
export const Route = createFileRoute('/invitation_/accepted')({
  loader: () => loadAcceptedPage(),
  component: InvitationAcceptedPage,
})

function InvitationAcceptedPage() {
  const { locale } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      compact
      title={t('invitationDoneTitle')}
      description={t('invitationDoneDescription')}
      titleIcon={<Check className="size-6" aria-hidden="true" />}
    >
      <a className={buttonVariants({ className: 'w-full' })} href="/account">
        {t('invitationSignIn')}
      </a>
    </AuthShell>
  )
}
