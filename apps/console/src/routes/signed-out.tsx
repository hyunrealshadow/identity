import { Button, Card } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'

import { Brand } from '#/components/app-navigation'
import { useAuth } from '#/lib/auth/context'
import { useTranslator } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'

export const Route = createFileRoute('/signed-out')({
  component: SignedOutPage,
})

function SignedOutPage() {
  const t = useTranslator()
  const config = useRuntimeConfig()
  const { signIn } = useAuth()

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground sm:p-6">
      <div className="w-full max-w-lg">
        <div className="mb-5 flex justify-center">
          <Brand displayName={config.displayName} />
        </div>
        <Card className="console-card border border-border">
          <Card.Header className="px-6 pt-6 text-center">
            <Card.Title className="text-xl font-semibold tracking-tight">
              {t('signedOutTitle')}
            </Card.Title>
            <Card.Description className="mt-2 text-sm leading-6 text-muted">
              {t('signedOutDescription')}
            </Card.Description>
          </Card.Header>
          <Card.Content className="px-6 pb-6 pt-4 text-center">
            <p className="text-sm leading-6 text-muted">{t('signedOutSsoNote')}</p>
            <Button className="mt-5" onPress={() => void signIn({ returnTo: '/' })}>
              {t('signInAgain')}
            </Button>
          </Card.Content>
        </Card>
      </div>
    </main>
  )
}
