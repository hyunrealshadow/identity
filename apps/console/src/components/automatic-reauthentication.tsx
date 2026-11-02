import type { ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { useAuth } from '#/lib/auth/context'
import { useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

/**
 * Keeps the workspace chrome out of the way while the central coordinator is
 * navigating for a challenge. Individual pages keep their real permission
 * denials because this gate only reacts to authentication recovery.
 */
export function AutomaticReauthenticationGate({ children }: { children: ReactNode }) {
  const t = useTranslator()
  const { status } = useAuth()
  const workspace = useWorkspace()

  if (status === 'authorizing' || workspace.status === 'reauth') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground sm:p-6">
        <div className="w-full max-w-lg">
          <AsyncState
            kind="loading"
            title={t('authReauthenticatingTitle')}
            description={t('authReauthenticatingDescription')}
          />
        </div>
      </main>
    )
  }

  return <>{children}</>
}
