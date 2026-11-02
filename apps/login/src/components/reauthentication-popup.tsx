import { Alert, Button } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { useServerFn } from '@tanstack/react-start'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { AccountActionInput, AccountActionResult } from '#/lib/account-action.server'
import { preflightAccountAction, type AccountAccessContext } from '#/lib/account-operations'
import { runAccountAction } from '#/lib/account-actions'
import { openAccountReauthPopup, safeAccountReauthReturnTo, verifyAccountReauthMessage, type AccountReauthRequest } from '#/lib/popup-reauth'
import { translate, type Locale } from '#/lib/i18n'

interface AccountReauthContextValue {
  requestReauth: (request: AccountReauthRequest) => void
  prepareAction: (action: string) => Promise<AccountActionResult & { localError?: string }>
  executeAction: (input: AccountActionInput) => Promise<AccountActionResult & { localError?: string }>
}
const AccountReauthContext = createContext<AccountReauthContextValue | null>(null)
export function useAccountReauth(): AccountReauthContextValue {
  const context = useContext(AccountReauthContext)
  const execute = useServerFn(runAccountAction)
  const fallback = useMemo<AccountReauthContextValue>(() => ({
    requestReauth: (request: AccountReauthRequest) => { window.location.assign(request.url) },
    prepareAction: async () => ({ ok: true }),
    executeAction: (input: AccountActionInput) => execute({ data: input }),
  }), [execute])
  return context ?? fallback
}

/** Owns one browser window; no authentication page is nested in the account UI. */
export function AccountReauthProvider({ locale, access, children }: { locale: Locale; access?: AccountAccessContext; children: ReactNode }) {
  const router = useRouter()
  const execute = useServerFn(runAccountAction)
  const popup = useRef<Window | null>(null)
  const pending = useRef<AccountReauthRequest | undefined>(undefined)
  const handled = useRef(false)
  const retrying = useRef(false)
  const [request, setRequest] = useState<AccountReauthRequest>()
  const [notice, setNotice] = useState<'blocked' | 'error'>()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  const cancel = useCallback(() => {
    handled.current = true
    pending.current = undefined
    popup.current?.close()
    popup.current = null
    setRequest(undefined)
    setNotice(undefined)
  }, [])
  const requestReauth = useCallback((next: AccountReauthRequest) => {
    // State is installed before navigating so even an immediate callback is bound.
    pending.current = next
    handled.current = false
    setRequest(next)
    const child = popup.current && !popup.current.closed ? popup.current : openAccountReauthPopup()
    popup.current = child
    if (!child) { setNotice('blocked'); return }
    setNotice(undefined)
    child.location.replace(next.url)
    child.focus()
  }, [])

  const prepareAction = useCallback(async (action: string): Promise<AccountActionResult & { localError?: string }> => {
    const decision = preflightAccountAction(action, access)
    if (decision.status === 'forbidden') {
      return { ok: false, localError: translate(locale, 'accountPermissionRequired') }
    }
    if (decision.status === 'reauthentication') {
      // The server resolves the challenge without receiving pending credentials.
      const result = await execute({ data: { action, values: {}, preflightOnly: true } })
      if (result.redirect) cancel()
      return result
    }
    return { ok: true }
  }, [access, cancel, execute, locale])
  const executeAction = useCallback(async (input: AccountActionInput) => {
    const prepared = await prepareAction(input.action)
    if (prepared.reauth || prepared.localError || !prepared.ok) return prepared
    // A stronger current server session may satisfy an older page snapshot.
    // No MFA occurred in this branch; this is still the original explicit action.
    const result = await execute({ data: input })
    if (result.redirect) cancel()
    return result
  }, [cancel, execute, prepareAction])

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      const current = pending.current
      if (!current || handled.current) return
      const message = verifyAccountReauthMessage({
        data: event.data, origin: event.origin, expectedOrigin: window.location.origin,
        source: event.source, expectedSource: popup.current, expectedState: current.state,
      })
      if (!message) return
      handled.current = true
      popup.current?.close()
      popup.current = null
      if (message.result !== 'success') { setNotice('error'); return }
      const returnTo = safeAccountReauthReturnTo(message.returnTo) ?? '/account/security'
      pending.current = undefined
      setRequest(undefined)
      setNotice(undefined)
      void (async () => {
        await router.invalidate()
        // Resume the editor, never replay the mutation that requested verification.
        await router.navigate({ href: returnTo })
      })()
    }
    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [router])
  useEffect(() => {
    if (!request) return
    const timer = window.setInterval(() => {
      if (pending.current !== request || !popup.current?.closed) return
      // An explicit close is a cancellation, not an automatic retry.
      cancel()
    }, 300)
    return () => window.clearInterval(timer)
  }, [cancel, request])
  useEffect(() => () => { popup.current?.close() }, [])

  const retry = useCallback(async () => {
    const current = pending.current
    if (!current || retrying.current) return
    retrying.current = true
    try {
      const result = await execute({ data: { action: 'retry-reauthentication', values: { state: current.state } } })
      if (pending.current !== current) return
      if (result.redirect) { cancel(); window.location.assign(result.redirect) }
      else if (result.reauth) requestReauth(result.reauth)
      else { popup.current?.close(); popup.current = null; setNotice('error') }
    } catch {
      if (pending.current === current) { popup.current?.close(); popup.current = null; setNotice('error') }
    } finally { retrying.current = false }
  }, [cancel, execute, requestReauth])

  const value = useMemo(() => ({ requestReauth, executeAction, prepareAction }), [requestReauth, executeAction, prepareAction])
  return <AccountReauthContext.Provider value={value}>
    {children}
    {notice && request ? <Alert status={notice === 'blocked' ? 'warning' : 'danger'} className="mt-4">
      <Alert.Indicator />
      <Alert.Content><Alert.Description>{t(notice === 'blocked' ? 'accountReauthPopupBlocked' : 'accountReauthFailed')}</Alert.Description>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" onPress={() => void retry()}>{t('accountReauthPopupContinue')}</Button>
          <Button size="sm" variant="ghost" onPress={() => window.location.assign(request.url)}>{t('accountReauthOpenWindow')}</Button>
          <Button size="sm" variant="ghost" onPress={cancel}>{t('close')}</Button>
        </div>
      </Alert.Content>
    </Alert> : null}
  </AccountReauthContext.Provider>
}
