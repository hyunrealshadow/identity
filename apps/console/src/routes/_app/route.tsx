import { Button } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { AppShell } from '#/components/app-shell'
import { AsyncState } from '#/components/async-state'
import { AutomaticReauthenticationGate } from '#/components/automatic-reauthentication'
import { SessionExpired } from '#/components/session-expired'
import { useAuth } from '#/lib/auth/context'
import { authErrorKey } from '#/lib/auth/messages'
import { currentReturnTo } from '#/lib/auth/return-to'
import { useTranslator } from '#/lib/i18n'
import { WorkspaceProvider } from '#/lib/workspace'

export const Route = createFileRoute('/_app')({
  component: AuthenticatedLayout,
})

function Centered({ children }: { children: ReactNode }) {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-2xl items-center justify-center p-4 sm:p-6">
      <div className="w-full">{children}</div>
    </main>
  )
}

function AuthenticatedLayout() {
  const t = useTranslator()
  const { status, errorCode, recoveryCorrelation, signIn, retryReauthentication } = useAuth()

  if (status === 'authenticated') {
    return (
      <WorkspaceProvider>
        <AutomaticReauthenticationGate>
          <AppShell />
        </AutomaticReauthenticationGate>
      </WorkspaceProvider>
    )
  }

  if (status === 'expired') {
    return (
      <Centered>
        <SessionExpired />
      </Centered>
    )
  }

  if (status === 'error') {
    const recoveryLoop = errorCode === 'reauthentication_loop'
    return (
      <Centered>
        <AsyncState
          kind="error"
          title={t(recoveryLoop ? 'authRecoveryTitle' : 'authFailedTitle')}
          description={t(
            recoveryLoop ? 'authRecoveryDescription' : authErrorKey(errorCode),
          )}
          requestId={recoveryCorrelation?.requestId}
          traceId={recoveryCorrelation?.traceId}
          onRetry={() =>
            void (recoveryLoop
              ? retryReauthentication()
              : signIn({ returnTo: currentReturnTo() }))
          }
        />
      </Centered>
    )
  }

  if (status === 'anonymous') {
    return (
      <Centered>
        <AsyncState
          kind="unauthorized"
          title={t('unauthorizedTitle')}
          description={t('unauthorizedDescription')}
          action={
            <Button onPress={() => void signIn({ returnTo: currentReturnTo() })}>
              {t('signInAgain')}
            </Button>
          }
        />
      </Centered>
    )
  }

  return (
    <Centered>
      <AsyncState
        kind="loading"
        title={t('loading')}
        description={t('authLoadingDescription')}
      />
    </Centered>
  )
}
