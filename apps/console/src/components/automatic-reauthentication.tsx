import type { ReactNode } from 'react'

import { FullPageLoading } from '#/components/full-page-loading'
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
    return <FullPageLoading label={t('authReauthenticatingTitle')} />
  }

  return <>{children}</>
}
