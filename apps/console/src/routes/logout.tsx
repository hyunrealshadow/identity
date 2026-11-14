import { Button } from '@identity/ui/components/button'
import { createFileRoute } from '@tanstack/react-router'

import { AuthStatusPage } from '#/components/auth-status-page'
import { useAuth } from '#/lib/auth/context'
import { useTranslator } from '#/lib/i18n'

export const Route = createFileRoute('/logout')({
  component: SignedOutPage,
})

function SignedOutPage() {
  const t = useTranslator()
  const { signIn } = useAuth()

  return (
    <AuthStatusPage
      tone="neutral"
      title={t('signedOutTitle')}
      description={t('signedOutDescription')}
      action={
        // The browser may still remember other accounts. Signing in again after
        // an explicit sign-out lets the user choose one instead of silently
        // continuing as whichever account remains.
        <Button onClick={() => void signIn({ selectAccount: true, returnTo: '/' })}>
          {t('signInAgain')}
        </Button>
      }
    />
  )
}
