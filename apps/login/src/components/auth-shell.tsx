import { Card, CardContent, CardDescription, CardHeader } from '@identity/ui/components/card'
import { cn } from '@identity/ui/lib/utils'
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
  tone?: 'default' | 'danger'
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
  tone = 'default',
}: AuthShellProps) {
  const danger = tone === 'danger'
  return (
    <main
      lang={lang}
      className="auth-background relative flex min-h-screen flex-col px-4 py-6 sm:px-6"
    >
      {/* The preference controls float above the card instead of taking a row:
          in normal flow they pushed the card below the viewport center. */}
      {showPreferences && locale ? (
        <div className="absolute top-6 right-4 z-10 sm:right-6">
          <AppearanceControls locale={locale} />
        </div>
      ) : null}
      <div className="flex flex-1 items-center justify-center py-4">
        <Card className={cn('auth-card relative w-full gap-0 py-0', wide ? 'max-w-[520px]' : 'max-w-[460px]')}>
          <CardHeader
            className={cn(
              'flex flex-col px-7 pt-9 min-[480px]:px-10',
              headerAlign === 'left' ? 'items-start text-left' : 'items-center text-center',
              compact ? 'pb-9' : 'pb-2',
            )}
          >
            {titleIcon ? (
              <div className={cn('auth-item mb-4 flex size-12 items-center justify-center rounded-full', danger ? 'bg-destructive/10 text-destructive' : 'bg-muted text-foreground')}>
                {titleIcon}
              </div>
            ) : null}
            <h1 data-slot="card-title" className={cn('auth-item auth-delay-1 text-[1.55rem] font-semibold tracking-tight', danger ? 'text-destructive' : 'text-foreground')}>
              {title}
            </h1>
            <CardDescription className={cn('auth-item auth-delay-2 mt-2 text-sm leading-6 text-balance', danger ? 'text-foreground' : 'text-muted-foreground', headerAlign === 'center' ? 'max-w-sm' : 'w-full')}>
              {description}
            </CardDescription>
          </CardHeader>
          {children ? (
            <CardContent className="auth-stagger relative px-7 pb-9 pt-6 min-[480px]:px-10">
              {children}
            </CardContent>
          ) : null}
        </Card>
      </div>
    </main>
  )
}
