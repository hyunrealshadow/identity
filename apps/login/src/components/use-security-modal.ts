import { useOverlayState } from '@heroui/react'
import { useNavigate, useRouter } from '@tanstack/react-router'
import { useServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'

import { runAccountAction } from '#/lib/account-actions'
import { translate, type Locale } from '#/lib/i18n'

/** Open security settings only after the backend authorizes the current session */
export function useSecurityModal({ action, locale, loginHint, openRequested = false }: {
  action: 'prepare-manage-passkeys' | 'prepare-mfa-preference'
  locale: Locale
  loginHint: string
  openRequested?: boolean
}) {
  const modal = useOverlayState()
  const execute = useServerFn(runAccountAction)
  const router = useRouter()
  const navigate = useNavigate()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const resumed = useRef(false)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const prepare = useCallback(async () => {
    if (inFlight.current) return
    inFlight.current = true
    setPending(true)
    setError('')
    try {
      const result = await execute({ data: { action, values: { login_hint: loginHint } } })
      if (!mounted.current) return
      if (result.redirect) { window.location.assign(result.redirect); return }
      if (!result.ok) {
        await router.invalidate()
        return
      }
      modal.open()
      if (openRequested) await navigate({ to: '/account/security', replace: true })
    } catch {
      if (mounted.current) setError(translate(locale, 'accountRequestFailed'))
    } finally {
      inFlight.current = false
      if (mounted.current) setPending(false)
    }
  }, [action, execute, locale, loginHint, modal.open, navigate, openRequested, router])

  useEffect(() => {
    if (!openRequested) { resumed.current = false; return }
    if (resumed.current) return
    resumed.current = true
    void prepare()
  }, [openRequested, prepare])

  return { modal, prepare, pending, error }
}
