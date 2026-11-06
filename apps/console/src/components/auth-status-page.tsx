import { Card } from '@heroui/react'
import { CircleAlert, LogOut } from 'lucide-react'
import type { ReactNode } from 'react'

type AuthStatusTone = 'error' | 'neutral'

/**
 * Standalone page for sign-in outcomes outside the workspace shell: a failed
 * callback and the signed-out confirmation. Waiting states use
 * `FullPageLoading` instead.
 */
export function AuthStatusPage({
  tone,
  title,
  description,
  action,
}: {
  tone: AuthStatusTone
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground sm:p-6">
      <div className="w-full max-w-md">
        <Card className="console-card border border-border">
          <Card.Content
            className="flex flex-col items-center px-6 py-8 text-center"
            role={tone === 'error' ? 'alert' : 'status'}
            aria-live={tone === 'error' ? 'assertive' : 'polite'}
          >
            <StatusIcon tone={tone} />
            <h1 className="mt-4 text-lg font-semibold tracking-tight">{title}</h1>
            {description ? (
              <p className="mt-2 max-w-sm text-sm leading-6 text-muted">{description}</p>
            ) : null}
            {action ? <div className="mt-6">{action}</div> : null}
          </Card.Content>
        </Card>
      </div>
    </main>
  )
}

function StatusIcon({ tone }: { tone: AuthStatusTone }) {
  const Icon = tone === 'error' ? CircleAlert : LogOut
  return (
    <span
      className={`flex size-11 items-center justify-center rounded-full ${
        tone === 'error' ? 'bg-danger/10 text-danger' : 'bg-surface-secondary text-muted'
      }`}
      aria-hidden="true"
    >
      <Icon className="size-5" />
    </span>
  )
}
