import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Card } from '@heroui/react'

import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

const loadHomePage = createServerFn({ method: 'GET' }).handler(async () => ({
  locale: requestLocale(),
}))

export const Route = createFileRoute('/')({
  loader: () => loadHomePage(),
  component: Home,
})

function Home() {
  const { locale } = Route.useLoaderData()

  return (
    <main
      lang={locale}
      className="auth-background flex min-h-screen items-center justify-center px-6"
    >
      <Card className="auth-card max-w-lg border border-black/[0.07] bg-white/90 p-8 text-center backdrop-blur-xl">
        <Card.Title className="auth-item auth-delay-1 text-2xl tracking-tight">
          {translate(locale, 'homeTitle')}
        </Card.Title>
        <Card.Description className="auth-item auth-delay-2 mt-3 leading-6">
          {translate(locale, 'homeDescription')}
        </Card.Description>
      </Card>
    </main>
  )
}
