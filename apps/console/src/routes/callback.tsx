import { Button, Card } from '@heroui/react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'

import { Brand } from '#/components/app-navigation'
import { AsyncState } from '#/components/async-state'
import { useAuth } from '#/lib/auth/context'
import {
  isPopupCallback,
  postCallbackToOpener,
} from '#/lib/auth/popup-reauthentication'
import { authErrorKey } from '#/lib/auth/messages'
import type { AuthErrorCode } from '#/lib/auth/transaction'
import { useTranslator } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'

export const Route = createFileRoute('/callback')({
  component: CallbackPage,
})

function CallbackPage() {
  const t = useTranslator()
  const config = useRuntimeConfig()
  const navigate = useNavigate()
  const { completeCallback, signIn } = useAuth()
  const [errorCode, setErrorCode] = useState<AuthErrorCode>()
  const [processing, setProcessing] = useState(true)
  const started = useRef(false)
  const popup = isPopupCallback()

  useEffect(() => {
    if (started.current) return
    started.current = true

    if (popup) {
      // The parent owns the PKCE transaction. This popup only reports where the
      // provider sent the browser back; it never consumes a transaction or
      // exchanges the authorization code.
      let targetOrigin = window.location.origin
      try {
        targetOrigin = new URL(config.redirectUri).origin
      } catch {
        // The current origin is the callback's only safe fallback.
      }
      postCallbackToOpener({ targetOrigin })
      return
    }

    void completeCallback(window.location.href)
      .then((returnTo) => {
        void navigate({ href: returnTo, replace: true })
      })
      .catch((error: unknown) => {
        setProcessing(false)
        setErrorCode(
          typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            typeof (error as { code: unknown }).code === 'string'
            ? (error as { code: AuthErrorCode }).code
            : undefined,
        )
      })
  }, [completeCallback, config.redirectUri, navigate, popup])

  if (popup) return null

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground sm:p-6">
      <div className="w-full max-w-lg">
        <div className="mb-5 flex justify-center">
          <Brand displayName={config.displayName} />
        </div>
        {processing ? (
          <AsyncState
            kind="loading"
            title={t('authCompletingTitle')}
            description={t('authCompletingDescription')}
          />
        ) : (
          <Card className="console-card border border-border">
            <Card.Content className="p-5">
              <AsyncState
                kind="error"
                title={t('authFailedTitle')}
                description={t(authErrorKey(errorCode))}
                action={
                  <Button onPress={() => void signIn({ returnTo: '/' })}>
                    {t('authRetry')}
                  </Button>
                }
              />
              <p className="mt-4 text-center text-xs text-muted">
                {t('authFailedDescription')}
              </p>
            </Card.Content>
          </Card>
        )}
      </div>
    </main>
  )
}
