import { createFileRoute } from '@tanstack/react-router'
import { Card } from '@heroui/react'
import { Fingerprint } from 'lucide-react'
import { translate } from '#/lib/i18n'

export const Route = createFileRoute('/')({ component: Home })

function Home() {
  return (
    <main className="auth-background flex min-h-screen items-center justify-center px-6">
      <Card className="max-w-lg border border-black/10 bg-white/95 p-8 text-center shadow-[0_24px_70px_-32px_rgba(0,0,0,0.35)]">
        <Fingerprint className="mx-auto size-10 text-accent" aria-hidden="true" />
        <Card.Title className="mt-4 text-2xl">{translate('en-US', 'homeTitle')}</Card.Title>
        <Card.Description className="mt-3 leading-6">
          {translate('en-US', 'homeDescription')}
        </Card.Description>
      </Card>
    </main>
  )
}
