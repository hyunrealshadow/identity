import { Card } from '@heroui/react'
import type { ReactNode } from 'react'

import { AppearanceControls } from '#/components/appearance-controls'
import type { Locale } from '#/lib/i18n'

interface AuthShellProps {
  title: string
  description: string
  children: ReactNode
  lang?: string
  locale?: Locale
  showPreferences?: boolean
}

export function AuthShell({
  title,
  description,
  children,
  lang,
  locale,
  showPreferences = false,
}: AuthShellProps) {
  return (
    <main
      lang={lang}
      className="auth-background flex min-h-screen items-center justify-center px-4 py-10 sm:px-6"
    >
      {showPreferences && locale ? <AppearanceControls locale={locale} /> : null}
      <Card className="auth-card relative w-full max-w-[460px] overflow-hidden border border-border bg-surface/90 backdrop-blur-xl">
        <Card.Header className="relative flex flex-col items-center px-7 pb-2 pt-9 text-center sm:px-10">
          <Card.Title className="auth-item auth-delay-1 text-[1.55rem] font-semibold tracking-tight text-foreground">
            {title}
          </Card.Title>
          <Card.Description className="auth-item auth-delay-2 mt-2 max-w-sm text-sm leading-6 text-muted">
            {description}
          </Card.Description>
        </Card.Header>
        <Card.Content className="auth-stagger relative px-7 pb-9 pt-6 sm:px-10">
          {children}
        </Card.Content>
      </Card>
    </main>
  )
}
