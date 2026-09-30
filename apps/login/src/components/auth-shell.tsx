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
  titleIcon?: ReactNode
  compact?: boolean
  wide?: boolean
  headerAlign?: 'center' | 'left'
}

export function AuthShell({
  title,
  description,
  children,
  lang,
  locale,
  showPreferences = false,
  titleIcon,
  compact = false,
  wide = false,
  headerAlign = 'center',
}: AuthShellProps) {
  return (
    <main
      lang={lang}
      className="auth-background flex min-h-screen items-center justify-center px-4 py-10 sm:px-6"
    >
      {showPreferences && locale ? <AppearanceControls locale={locale} /> : null}
      <Card className={`auth-card relative w-full overflow-hidden border border-border bg-surface/90 backdrop-blur-xl ${wide ? 'max-w-[520px]' : 'max-w-[460px]'}`}>
        <Card.Header className={`relative flex flex-col px-7 pt-9 sm:px-10 ${headerAlign === 'left' ? 'items-start text-left' : 'items-center text-center'} ${compact ? 'pb-9' : 'pb-2'}`}>
          {titleIcon ? (
            <div className="auth-item mb-4 flex size-12 items-center justify-center rounded-full bg-surface-secondary text-foreground">
              {titleIcon}
            </div>
          ) : null}
          <Card.Title className="auth-item auth-delay-1 text-[1.55rem] font-semibold tracking-tight text-foreground">
            {title}
          </Card.Title>
          <Card.Description className={`auth-item auth-delay-2 mt-2 text-sm leading-6 text-muted ${headerAlign === 'center' ? 'max-w-sm' : 'w-full'}`}>
            {description}
          </Card.Description>
        </Card.Header>
        {children ? (
          <Card.Content className="auth-stagger relative px-7 pb-9 pt-6 sm:px-10">
            {children}
          </Card.Content>
        ) : null}
      </Card>
    </main>
  )
}
