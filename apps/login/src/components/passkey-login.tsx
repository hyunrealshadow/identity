import { Button } from '@heroui/react'
import { createServerFn } from '@tanstack/react-start'
import { Fingerprint } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'

import { errorMessage, identityJson } from '#/lib/identity.server'
import type { ChallengeResponse } from '#/lib/identity-types'
import { translate, type Locale } from '#/lib/i18n'
import { getPasskey, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'

const begin = createServerFn({ method: 'POST' })
  .validator((data: { loginId: string; csrfToken: string }) => data)
  .handler(async ({ data }) => JSON.stringify(await identityJson<PasskeyOptions>('/api/auth/login/passkey/options', {
    method: 'POST', csrfToken: data.csrfToken, body: { id: data.loginId },
  })))

const finish = createServerFn({ method: 'POST' })
  .validator((data: { loginId: string; csrfToken: string; assertion: string; locale: Locale }) => data)
  .handler(async ({ data }) => {
    try {
      const result = await identityJson<ChallengeResponse>('/api/auth/login/challenge', {
        method: 'POST', csrfToken: data.csrfToken,
        body: { id: data.loginId, credential_type: 'passkey', credential: data.assertion },
      })
      return { redirect: result.continue_uri }
    } catch (error) {
      return { error: errorMessage(error, data.locale) }
    }
  })

export function PasskeyLogin({ loginId, csrfToken, locale, primary = false }: { loginId: string; csrfToken: string; locale: Locale; primary?: boolean }) {
  const [supported, setSupported] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const activeRequest = useRef<AbortController | null>(null)
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  const signIn = useCallback(async () => {
    if (activeRequest.current) return
    const controller = new AbortController()
    activeRequest.current = controller
    setBusy(true)
    setError('')
    try {
      const options = JSON.parse(await begin({ data: { loginId, csrfToken } })) as PasskeyOptions
      if (controller.signal.aborted) return
      const assertion = await getPasskey(options, controller.signal)
      if (controller.signal.aborted) return
      const result = await finish({ data: { loginId, csrfToken, assertion: JSON.stringify(assertion), locale } })
      if (controller.signal.aborted) return
      if (result.redirect) window.location.assign(result.redirect)
      else setError(result.error ?? translate(locale, 'passkeyFailed'))
    } catch (error) {
      if (!controller.signal.aborted) {
        setError(translate(locale, error instanceof Error && error.name === 'NotAllowedError' ? 'passkeyCancelled' : 'passkeyFailed'))
      }
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null
        setBusy(false)
      }
    }
  }, [loginId, csrfToken, locale])

  useEffect(() => {
    const canUsePasskeys = passkeysSupported()
    setSupported(canUsePasskeys)
    setBusy(false)
    let timer: number | undefined
    const startWhenFocused = () => {
      if (document.visibilityState === 'hidden' || !document.hasFocus()) return
      window.removeEventListener('focus', startWhenFocused)
      document.removeEventListener('visibilitychange', startWhenFocused)
      // Defer so an effect cleanup (including Strict Mode) can cancel the start.
      timer = window.setTimeout(() => void signIn(), 0)
    }
    if (primary && canUsePasskeys) {
      window.addEventListener('focus', startWhenFocused)
      document.addEventListener('visibilitychange', startWhenFocused)
      startWhenFocused()
    }
    return () => {
      window.clearTimeout(timer)
      window.removeEventListener('focus', startWhenFocused)
      document.removeEventListener('visibilitychange', startWhenFocused)
      activeRequest.current?.abort()
      activeRequest.current = null
    }
  }, [primary, signIn])

  return <div className="space-y-2">
    <Button fullWidth variant={primary ? 'primary' : 'secondary'} isDisabled={!supported || busy} isPending={busy} onPress={() => void signIn()}>
      <Fingerprint className="size-4" aria-hidden="true" />{t('usePasskey')}
    </Button>
    <p className="no-js-only text-xs text-muted">{t('passkeyRequiresJavascript')}</p>
    {!supported ? <p className="js-only text-xs text-muted">{t('passkeyUnsupported')}</p> : null}
    {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
  </div>
}
