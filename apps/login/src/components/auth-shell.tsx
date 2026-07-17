import { Card } from '@heroui/react'
import { Fingerprint } from 'lucide-react'
import type { ReactNode } from 'react'

interface AuthShellProps {
  title: string
  description: string
  children: ReactNode
  eyebrow?: string
  lang?: string
}

export function AuthShell({
  title,
  description,
  children,
  eyebrow = 'Identity',
  lang,
}: AuthShellProps) {
  return (
    <main lang={lang} className="auth-background flex min-h-screen items-center justify-center px-4 py-10 sm:px-6">
      <Card className="relative w-full max-w-[460px] overflow-hidden border border-black/10 bg-white/95 shadow-[0_24px_70px_-32px_rgba(0,0,0,0.35),0_2px_8px_rgba(0,0,0,0.04)] backdrop-blur-xl">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-black/45 to-transparent" />
        <Card.Header className="flex flex-col items-center px-7 pb-2 pt-8 text-center sm:px-10">
          <div className="mb-5 flex size-14 items-center justify-center rounded-2xl bg-accent text-accent-foreground shadow-lg shadow-black/15">
            <Fingerprint aria-hidden="true" className="size-7" />
          </div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.22em] text-muted">
            {eyebrow}
          </p>
          <Card.Title className="text-2xl font-semibold tracking-tight text-foreground">
            {title}
          </Card.Title>
          <Card.Description className="mt-2 max-w-sm text-sm leading-6 text-muted">
            {description}
          </Card.Description>
        </Card.Header>
        <Card.Content className="px-7 pb-8 pt-5 sm:px-10">
          {children}
        </Card.Content>
      </Card>
    </main>
  )
}
