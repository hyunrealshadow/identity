import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { ReauthenticationPopup } from '#/components/reauthentication-popup'
import { SessionVersionContext } from '#/lib/auth/session-version'
import { clearCurrentDrafts } from '#/lib/draft-storage'
import { queryClient } from '#/lib/graphql/query-client'

import { emitAuthLogout, emitBeforeAuthRedirect } from '#/lib/auth/events'
import {
  POPUP_CLOSED_POLL_MS,
  PopupCallbackGuard,
  closeAuthenticationPopup,
  openAuthenticationPopup,
  popupWindowName,
  type PopupReauthenticationPrompt,
} from '#/lib/auth/popup-reauthentication'
import {
  beginAuthorization,
  buildEndSessionUrl,
  completeAuthorization,
  type StepUpRequest,
} from '#/lib/auth/oidc'
import {
  clearReauthenticationMarker,
  completeReauthenticationMarker,
  isImmediateReauthenticationLoop,
  readReauthenticationMarker,
  saveReauthenticationMarker,
  type ReauthenticationTrigger,
} from '#/lib/auth/reauthentication'
import { currentReturnTo, sanitizeReturnTo } from '#/lib/auth/return-to'
import { assignDocument, reloadDocument } from '#/lib/auth/navigation'
import {
  clearAuthSession,
  getAuthSession,
  peekAccessToken,
  setAuthSession,
  type IdTokenClaims,
} from '#/lib/auth/session'
import {
  AUTH_TRANSACTION_KEY,
  AuthError,
  consumeTransaction,
  validateTransaction,
  type AuthErrorCode,
  type AuthTransaction,
} from '#/lib/auth/transaction'
import { useLocale } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'

export type AuthStatus =
  | 'booting'
  | 'authorizing'
  | 'authenticated'
  | 'anonymous'
  /** Leaving for the provider's end-session endpoint. */
  | 'signingOut'
  | 'expired'
  | 'error'

export interface SignInOptions {
  returnTo?: string
  stepUp?: StepUpRequest
  acrValues?: string
  /** Explicit account selection for a normal sign-in; never combined with stepUp. */
  selectAccount?: boolean
}

export interface ReauthenticationOptions {
  returnTo?: string
  reason?: ReauthenticationTrigger
  requestId?: string
  traceId?: string
  /** Explicit user retry bypasses only the short automatic loop window. */
  manual?: boolean
}

interface AuthContextValue {
  status: AuthStatus
  errorCode?: AuthErrorCode
  recoveryCorrelation?: { requestId?: string; traceId?: string }
  claims?: IdTokenClaims
  ssoAvailable: boolean
  /** Increments whenever a new usable session replaces the previous one. */
  sessionVersion: number
  /** The parent-owned popup attempt, if a fresh-authentication window is open. */
  reauthenticationPopup: PopupReauthenticationPrompt | null
  signIn: (options?: SignInOptions) => Promise<void>
  requireReauthentication: (
    challenge?: StepUpRequest,
    options?: ReauthenticationOptions,
  ) => Promise<void>
  retryReauthentication: () => Promise<void>
  cancelReauthentication: () => void
  completeCallback: (callbackUrl: string) => Promise<string>
  expire: () => void
  logoutLocal: () => void
  logoutSso: () => boolean
  accessToken: () => string | null
}

const AuthContext = createContext<AuthContextValue | null>(null)

function currentPath(): string {
  return typeof window === 'undefined' ? '/' : window.location.pathname
}

function clearTransientPageData(): void {
  // Cached GraphQL reads belong to one authenticated session. Signing out
  // removes them before another account can mount the workspace.
  queryClient.clear()
  try {
    window.sessionStorage.removeItem(AUTH_TRANSACTION_KEY)
  } catch {
    // Storage may be blocked; in-memory state is still cleared.
  }
}

function redirectPath(redirectUri: string): string {
  try {
    return new URL(redirectUri).pathname.replace(/\/+$/, '') || '/'
  } catch {
    return '/callback'
  }
}

/** Non-empty claims values are routing hints only, never proof of identity. */
function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0
    ? value
    : undefined
}

function loginHintFromClaims(
  claims: IdTokenClaims | undefined,
): string | undefined {
  if (!claims) return undefined
  return (
    nonEmptyString(claims.preferred_username) ?? nonEmptyString(claims.email)
  )
}

function errorCodeOf(error: unknown, fallback: AuthErrorCode): AuthErrorCode {
  return error instanceof AuthError ? error.code : fallback
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const config = useRuntimeConfig()
  const { locale, t, applyAccountLocale, applyAccountTimeZone } = useLocale()
  const [status, setStatus] = useState<AuthStatus>(() =>
    getAuthSession() ? 'authenticated' : 'booting',
  )
  const [errorCode, setErrorCode] = useState<AuthErrorCode>()
  const [recoveryCorrelation, setRecoveryCorrelation] = useState<{
    requestId?: string
    traceId?: string
  }>()
  const [claims, setClaims] = useState<IdTokenClaims | undefined>(
    () => getAuthSession()?.claims,
  )
  const [endSessionEndpoint, setEndSessionEndpoint] = useState<
    string | undefined
  >(() => getAuthSession()?.endSessionEndpoint)
  const [sessionVersion, setSessionVersion] = useState(0)
  const [popupPrompt, setPopupPrompt] =
    useState<PopupReauthenticationPrompt | null>(null)

  useEffect(() => {
    // Every usable session replacement starts with an empty read cache, so a
    // page can never render capabilities or entities of its predecessor.
    queryClient.clear()
  }, [sessionVersion])

  const startedRef = useRef(false)
  const redirectInFlightRef = useRef<Promise<void> | null>(null)
  const explicitlySignedOutRef = useRef(false)
  const popupPromptRef = useRef<PopupReauthenticationPrompt | null>(null)
  const popupFlowRef = useRef<Promise<void> | null>(null)
  const popupAttemptRef = useRef(0)
  const popupGuardRef = useRef<PopupCallbackGuard | null>(null)
  const popupWindowRef = useRef<Window | null>(null)

  const updatePopupPrompt = useCallback(
    (next: PopupReauthenticationPrompt | null) => {
      popupPromptRef.current = next
      setPopupPrompt(next)
    },
    [],
  )

  const closePopupWindow = useCallback(() => {
    closeAuthenticationPopup(popupWindowRef.current)
    popupWindowRef.current = null
  }, [])

  const closePopupPrompt = useCallback(() => {
    popupAttemptRef.current += 1
    popupPromptRef.current = null
    popupFlowRef.current = null
    popupGuardRef.current = null
    closePopupWindow()
    setPopupPrompt(null)
  }, [closePopupWindow])

  const signIn = useCallback(
    async (options: SignInOptions = {}) => {
      if (options.selectAccount && options.stepUp) {
        // Never trade a subject-bound step-up for account selection.
        setErrorCode('invalid_transaction')
        setStatus('error')
        return
      }

      explicitlySignedOutRef.current = false
      redirectInFlightRef.current = null
      closePopupPrompt()
      const session = getAuthSession()
      const switchingAccount = options.selectAccount === true
      // A normal interactive sign-in while an old in-memory session still
      // exists is still a reauthentication transition for draft listeners.
      // The event must stay synchronous and happen while the old subject is
      // readable so subject-scoped drafts are captured first.
      if (session) emitBeforeAuthRedirect()
      if (switchingAccount) clearReauthenticationMarker()
      setErrorCode(undefined)
      setRecoveryCorrelation(undefined)
      setStatus('authorizing')

      try {
        await beginAuthorization({
          config,
          locale,
          returnTo: options.returnTo ?? currentReturnTo(),
          stepUp: options.stepUp,
          // The management console requests AAL2 for ordinary sign-in, but it
          // deliberately omits max_age so read-only users are not forced into
          // a recent-authentication window.
          acrValues: options.stepUp ? undefined : (options.acrValues ?? 'aal2'),
          // Only an explicit step-up uses the current session as a routing hint
          // and an identity binding. Ordinary and switch-account sign-in send
          // neither.
          loginHint: options.stepUp
            ? loginHintFromClaims(session?.claims)
            : undefined,
          expectedSubject: options.stepUp
            ? nonEmptyString(session?.claims.sub)
            : undefined,
          selectAccount: switchingAccount,
          beforeRedirect: () => {
            if (!switchingAccount) return
            // The authorization request has already been created and stored.
            // Only now discard the previous identity, so a discovery or
            // request-validation failure leaves the old session usable.
            clearReauthenticationMarker()
            applyAccountLocale(null)
            applyAccountTimeZone(null)
            clearAuthSession()
            setClaims(undefined)
            setEndSessionEndpoint(undefined)
          },
        })
      } catch (error) {
        redirectInFlightRef.current = null
        setErrorCode(errorCodeOf(error, 'discovery_failed'))
        if (session) {
          // A failed request must not destroy an account that was usable before
          // the switch was attempted.
          setAuthSession(session)
          applyAccountLocale(session.claims.locale)
          applyAccountTimeZone(session.claims.zoneinfo)
          setClaims(session.claims)
          setEndSessionEndpoint(session.endSessionEndpoint)
          setStatus(
            session.expiresAt > Date.now() ? 'authenticated' : 'expired',
          )
        } else {
          setStatus('error')
        }
      }
    },
    [
      applyAccountLocale,
      applyAccountTimeZone,
      closePopupPrompt,
      config,
      locale,
    ],
  )

  const startTopLevelReauthentication = useCallback(
    (
      challenge: StepUpRequest | undefined,
      options: ReauthenticationOptions,
      session: ReturnType<typeof getAuthSession>,
    ): Promise<void> => {
      const returnTo = sanitizeReturnTo(options.returnTo ?? currentReturnTo())
      const startedAt = Date.now()
      setRecoveryCorrelation({
        requestId: options.requestId,
        traceId: options.traceId,
      })

      if (!options.manual && session) {
        const marker = readReauthenticationMarker(undefined, startedAt)
        const identity = {
          subject: session.claims.sub,
          issuer: session.claims.iss,
          returnTo,
        }
        if (isImmediateReauthenticationLoop(marker, identity, startedAt)) {
          // One global recoverable error, not another authorize round-trip.
          if (session) emitBeforeAuthRedirect()
          setErrorCode('reauthentication_loop')
          setStatus('error')
          const settled = Promise.resolve()
          redirectInFlightRef.current = settled
          return settled
        }
      }

      const subject = session?.claims.sub
      const issuer = session?.claims.iss
      // Capture the current identity before clearing the in-memory session.
      // The hint is a routing convenience; expectedSubject is the binding.
      const loginHint = challenge
        ? loginHintFromClaims(session?.claims)
        : undefined
      const expectedSubject = challenge ? nonEmptyString(subject) : undefined

      const run = (async () => {
        // Fire before any status change, unmount or session clear so the event
        // listener can still read the previous subject.
        if (session) emitBeforeAuthRedirect()
        setErrorCode(undefined)
        setStatus('authorizing')

        try {
          await beginAuthorization({
            config,
            locale,
            returnTo,
            // Expired or rejected credentials require ordinary sign-in, not
            // an assurance/freshness challenge against the invalid session.
            stepUp: challenge
              ? { acrValues: challenge.acrValues ?? 'aal2', maxAge: 0 }
              : undefined,
            acrValues: challenge ? undefined : 'aal2',
            loginHint,
            expectedSubject,
            beforeRedirect: (request) => {
              if (session) {
                applyAccountLocale(null)
                applyAccountTimeZone(null)
                clearAuthSession()
                setClaims(undefined)
                setEndSessionEndpoint(undefined)
              }
              if (!subject || !issuer) {
                clearReauthenticationMarker()
                return
              }
              saveReauthenticationMarker({
                version: 1,
                phase: 'pending',
                subject,
                issuer,
                returnTo,
                state: request.transaction.state,
                startedAt: request.transaction.createdAt,
                expiresAt: request.transaction.expiresAt,
              })
            },
          })
        } catch (error) {
          clearReauthenticationMarker()
          redirectInFlightRef.current = null
          setErrorCode(errorCodeOf(error, 'discovery_failed'))
          if (session) {
            setAuthSession(session)
            applyAccountLocale(session.claims.locale)
            applyAccountTimeZone(session.claims.zoneinfo)
            setClaims(session.claims)
            setEndSessionEndpoint(session.endSessionEndpoint)
            setStatus(
              session.expiresAt > Date.now() ? 'authenticated' : 'expired',
            )
          } else {
            setStatus('error')
          }
        }
      })()

      redirectInFlightRef.current = run
      return run
    },
    [applyAccountLocale, applyAccountTimeZone, config, locale],
  )

  const activatePopup = useCallback(
    (
      prompt: PopupReauthenticationPrompt,
      request: { url: string; transaction: AuthTransaction },
      attempt: number,
    ) => {
      if (popupAttemptRef.current !== attempt) return
      const popup = popupWindowRef.current
      if (!popup || popup.closed) {
        popupWindowRef.current = null
        updatePopupPrompt({
          ...prompt,
          phase: 'blocked',
          authorizeUrl: request.url,
          transaction: request.transaction,
        })
        return
      }

      try {
        popup.location.replace(request.url)
      } catch {
        closePopupWindow()
        updatePopupPrompt({
          ...prompt,
          phase: 'failed',
          errorCode: 'discovery_failed',
        })
        return
      }

      popupGuardRef.current = new PopupCallbackGuard()
      updatePopupPrompt({
        ...prompt,
        phase: 'waiting',
        authorizeUrl: request.url,
        transaction: request.transaction,
      })

      if (prompt.subject && prompt.issuer) {
        saveReauthenticationMarker({
          version: 1,
          phase: 'pending',
          subject: prompt.subject,
          issuer: prompt.issuer,
          returnTo: prompt.returnTo,
          state: request.transaction.state,
          startedAt: request.transaction.createdAt,
          expiresAt: request.transaction.expiresAt,
        })
      }
    },
    [closePopupWindow, updatePopupPrompt],
  )

  const startPopupReauthentication = useCallback(
    (
      challenge: StepUpRequest | undefined,
      options: ReauthenticationOptions,
      session: NonNullable<ReturnType<typeof getAuthSession>>,
    ): Promise<void> => {
      if (popupPromptRef.current) {
        return popupFlowRef.current ?? Promise.resolve()
      }
      if (redirectInFlightRef.current) return redirectInFlightRef.current

      const returnTo = sanitizeReturnTo(options.returnTo ?? currentReturnTo())
      const startedAt = Date.now()

      if (!options.manual) {
        const marker = readReauthenticationMarker(undefined, startedAt)
        const identity = {
          subject: session.claims.sub,
          issuer: session.claims.iss,
          returnTo,
        }
        if (isImmediateReauthenticationLoop(marker, identity, startedAt)) {
          setRecoveryCorrelation({
            requestId: options.requestId,
            traceId: options.traceId,
          })
          setErrorCode('reauthentication_loop')
          setStatus('error')
          return Promise.resolve()
        }
      }

      const subject = nonEmptyString(session.claims.sub)
      // The hint is a routing convenience; expectedSubject is the binding that
      // completeAuthorization checks after validating the ID token.
      const loginHint = loginHintFromClaims(session.claims)
      const attempt = popupAttemptRef.current + 1
      popupAttemptRef.current = attempt
      popupGuardRef.current = null
      setRecoveryCorrelation({
        requestId: options.requestId,
        traceId: options.traceId,
      })
      setErrorCode(undefined)
      // The workspace stays authenticated and its old claims remain visible.
      // Only a successful callback replaces the session.
      setStatus('authenticated')

      // Reserve the window synchronously, before discovery or any other await,
      // so a popup blocker can accept an automatic or user-triggered attempt.
      const popup = openAuthenticationPopup({
        name: popupWindowName(attempt),
        title: t('authPopupLoadingTitle'),
      })
      popupWindowRef.current = popup

      const initial: PopupReauthenticationPrompt = {
        phase: popup ? 'starting' : 'blocked',
        returnTo,
        reason: options.reason ?? 'policy',
        challenge,
        requestId: options.requestId,
        traceId: options.traceId,
        subject,
        issuer: nonEmptyString(session.claims.iss),
      }
      updatePopupPrompt(initial)

      const run = (async () => {
        try {
          const request = await beginAuthorization({
            config,
            locale,
            returnTo,
            stepUp: {
              acrValues: challenge?.acrValues ?? 'aal2',
              maxAge: 0,
            },
            loginHint,
            expectedSubject: subject,
            selectAccount: false,
            // Keep the PKCE transaction in this parent window. The popup only
            // reports its callback URL back through postMessage.
            deferNavigation: true,
          })

          if (popupAttemptRef.current !== attempt) return
          const current = popupPromptRef.current
          if (!current) return
          if (!request) {
            // An incompatible implementation returned no request; keep the
            // attempt visible and single rather than silently starting again.
            closePopupWindow()
            updatePopupPrompt({
              ...current,
              phase: 'failed',
              errorCode: 'discovery_failed',
            })
            return
          }

          activatePopup(current, request, attempt)
        } catch (error) {
          if (popupAttemptRef.current !== attempt) return
          const current = popupPromptRef.current
          if (!current) return
          closePopupWindow()
          const failed: PopupReauthenticationPrompt = {
            ...current,
            phase: 'failed',
            errorCode: errorCodeOf(error, 'discovery_failed'),
          }
          updatePopupPrompt(failed)
        } finally {
          if (popupAttemptRef.current === attempt) popupFlowRef.current = null
        }
      })()

      popupFlowRef.current = run
      return run
    },
    [activatePopup, closePopupWindow, config, locale, t, updatePopupPrompt],
  )

  const requireReauthentication = useCallback(
    (challenge?: StepUpRequest, options: ReauthenticationOptions = {}) => {
      if (explicitlySignedOutRef.current) return Promise.resolve()
      if (redirectInFlightRef.current) return redirectInFlightRef.current

      const session = getAuthSession()
      const canStepUp =
        challenge &&
        session &&
        session.expiresAt > Date.now() &&
        options.reason !== 'unauthorized' &&
        options.reason !== 'expiry'
      if (canStepUp) {
        if (popupPromptRef.current) {
          return popupFlowRef.current ?? Promise.resolve()
        }
        return startPopupReauthentication(challenge, options, session)
      }

      // A server rejection supersedes an outstanding step-up. Capture drafts
      // from the old subject, then leave through ordinary top-level sign-in.
      closePopupPrompt()
      return startTopLevelReauthentication(undefined, options, session)
    },
    [
      closePopupPrompt,
      startPopupReauthentication,
      startTopLevelReauthentication,
    ],
  )

  const retryReauthentication = useCallback(async () => {
    clearReauthenticationMarker()
    closePopupPrompt()
    redirectInFlightRef.current = null
    explicitlySignedOutRef.current = false
    await startTopLevelReauthentication(
      undefined,
      { reason: 'manual', manual: true },
      getAuthSession(),
    )
  }, [closePopupPrompt, startTopLevelReauthentication])

  const retryPopupReauthentication = useCallback(() => {
    const current = popupPromptRef.current
    if (!current) {
      void retryReauthentication()
      return
    }
    const { challenge, returnTo, requestId, traceId } = current
    const session = getAuthSession()
    closePopupPrompt()
    redirectInFlightRef.current = null
    clearReauthenticationMarker()
    void (session
      ? startPopupReauthentication(
          challenge,
          {
            returnTo,
            reason: 'manual',
            requestId,
            traceId,
            manual: true,
          },
          session,
        )
      : startTopLevelReauthentication(
          challenge,
          {
            returnTo,
            reason: 'manual',
            requestId,
            traceId,
            manual: true,
          },
          null,
        ))
  }, [
    closePopupPrompt,
    retryReauthentication,
    startPopupReauthentication,
    startTopLevelReauthentication,
  ])

  /**
   * The explicit Continue action. It reserves the popup synchronously before
   * reusing a ready request or waiting for discovery to finish. A blocked or
   * closed window stays blocked instead of auto-opening again.
   */
  const continuePopupReauthentication = useCallback(() => {
    const current = popupPromptRef.current
    if (!current) {
      void retryReauthentication()
      return
    }
    if (current.phase === 'failed') {
      retryPopupReauthentication()
      return
    }
    if (current.phase !== 'blocked') return
    if (current.transaction && current.transaction.expiresAt <= Date.now()) {
      // A retained request past its TTL is a new attempt, still opened from
      // this click before any discovery.
      retryPopupReauthentication()
      return
    }

    const attempt = popupAttemptRef.current
    const popup = openAuthenticationPopup({
      name: popupWindowName(attempt),
      title: t('authPopupLoadingTitle'),
    })
    if (!popup) return
    popupWindowRef.current = popup

    if (current.authorizeUrl && current.transaction) {
      activatePopup(
        current,
        {
          url: current.authorizeUrl,
          transaction: current.transaction,
        },
        attempt,
      )
      return
    }
    updatePopupPrompt({ ...current, phase: 'starting' })
  }, [
    activatePopup,
    retryPopupReauthentication,
    retryReauthentication,
    t,
    updatePopupPrompt,
  ])

  const fallbackToTopLevelReauthentication = useCallback(() => {
    const current = popupPromptRef.current
    if (!current) return
    const { challenge, returnTo, requestId, traceId } = current
    const session = getAuthSession()
    closePopupPrompt()
    clearReauthenticationMarker()
    void startTopLevelReauthentication(
      challenge,
      {
        returnTo,
        reason: 'manual',
        requestId,
        traceId,
        manual: true,
      },
      session,
    )
  }, [closePopupPrompt, startTopLevelReauthentication])

  const cancelReauthentication = useCallback(() => {
    const session = getAuthSession()

    clearReauthenticationMarker()
    closePopupPrompt()

    // A previous usable session is left untouched. When that session has
    // already expired, show the existing explicit recovery screen instead of
    // silently reopening the popup.
    if (!session || session.expiresAt <= Date.now()) {
      setStatus('expired')
    } else {
      setStatus('authenticated')
    }
  }, [closePopupPrompt])

  const completePopupCallback = useCallback(
    async (transaction: AuthTransaction, callbackUrl: string) => {
      const current = popupPromptRef.current
      if (
        !current ||
        current.phase !== 'waiting' ||
        current.transaction?.state !== transaction.state
      ) {
        return
      }

      const attempt = popupAttemptRef.current
      const completing: PopupReauthenticationPrompt = {
        ...current,
        phase: 'completing',
      }
      updatePopupPrompt(completing)

      try {
        const session = await completeAuthorization({
          config,
          callbackUrl,
          transaction,
        })
        if (popupAttemptRef.current !== attempt) return

        setAuthSession(session)
        setRecoveryCorrelation(undefined)
        // A valid callback completes the automatic attempt for this exact
        // transaction and principal before the workspace can challenge again.
        completeReauthenticationMarker({
          state: transaction.state,
          subject: session.claims.sub,
          issuer: session.claims.iss,
        })
        explicitlySignedOutRef.current = false
        redirectInFlightRef.current = null
        applyAccountLocale(session.claims.locale)
        applyAccountTimeZone(session.claims.zoneinfo)
        setClaims(session.claims)
        setEndSessionEndpoint(session.endSessionEndpoint)
        setErrorCode(undefined)
        // Refetch consumers with the new session without unmounting the workspace.
        setSessionVersion((version) => version + 1)
        closePopupPrompt()
        setStatus('authenticated')
      } catch (error) {
        if (popupAttemptRef.current !== attempt) return
        clearReauthenticationMarker()
        closePopupWindow()
        // Keep the old session, claims, locale and visible workspace intact.
        const failed: PopupReauthenticationPrompt = {
          ...current,
          phase: 'failed',
          errorCode: errorCodeOf(error, 'exchange_failed'),
        }
        updatePopupPrompt(failed)
      }
    },
    [
      applyAccountLocale,
      applyAccountTimeZone,
      closePopupPrompt,
      closePopupWindow,
      config,
      updatePopupPrompt,
    ],
  )

  useEffect(() => {
    if (
      !popupPrompt ||
      popupPrompt.phase !== 'waiting' ||
      !popupPrompt.transaction
    ) {
      return
    }

    let expectedOrigin: string
    try {
      expectedOrigin = new URL(config.redirectUri).origin
    } catch {
      return
    }

    const onMessage = (event: MessageEvent) => {
      const guard = popupGuardRef.current
      const current = popupPromptRef.current
      if (
        !guard ||
        !current ||
        current.phase !== 'waiting' ||
        !current.transaction
      )
        return

      const result = guard.accept({
        event: {
          origin: event.origin,
          source: event.source,
          data: event.data,
        },
        expectedOrigin,
        expectedSource: popupWindowRef.current,
        redirectUri: config.redirectUri,
        transaction: current.transaction,
      })
      if (!result.ok) return

      void completePopupCallback(current.transaction, result.callbackUrl)
    }

    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [completePopupCallback, config.redirectUri, popupPrompt])

  useEffect(() => {
    if (!popupPrompt) return
    const popup = popupWindowRef.current
    if (!popup) return
    const attempt = popupAttemptRef.current
    const timer = window.setInterval(() => {
      if (popupAttemptRef.current !== attempt) return
      if (!popup.closed) return
      const current = popupPromptRef.current
      if (!current || current.phase === 'completing') return
      cancelReauthentication()
    }, POPUP_CLOSED_POLL_MS)
    return () => window.clearInterval(timer)
  }, [cancelReauthentication, popupPrompt])

  useEffect(
    () => () => {
      closeAuthenticationPopup(popupWindowRef.current)
      popupWindowRef.current = null
    },
    [],
  )

  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true

    const session = getAuthSession()
    if (session) {
      setClaims(session.claims)
      setEndSessionEndpoint(session.endSessionEndpoint)
      applyAccountLocale(session.claims.locale)
      applyAccountTimeZone(session.claims.zoneinfo)
      setStatus('authenticated')
      return
    }

    const path = currentPath().replace(/\/+$/, '') || '/'
    if (path === redirectPath(config.redirectUri) || path === redirectPath(config.postLogoutRedirectUri)) {
      setStatus('anonymous')
      return
    }

    void signIn({ returnTo: currentReturnTo() })
  }, [applyAccountLocale, applyAccountTimeZone, config.redirectUri, config.postLogoutRedirectUri, signIn])

  useEffect(() => {
    if (status !== 'authorizing' && status !== 'signingOut') return
    // Returning from the provider with the browser's Back button can restore
    // this document from the back/forward cache, frozen in the state it had
    // while leaving. Nothing would ever finish that redirect, and an account
    // switch or sign-out has already discarded the in-memory session, so start
    // over from a fresh document instead of showing a permanent spinner.
    const onPageShow = (event: PageTransitionEvent) => {
      if (event.persisted) reloadDocument()
    }
    window.addEventListener('pageshow', onPageShow)
    return () => window.removeEventListener('pageshow', onPageShow)
  }, [status])

  useEffect(() => {
    if (status !== 'authenticated') return
    const session = getAuthSession()
    if (!session) return

    const expireNow = () => {
      void requireReauthentication(undefined, { reason: 'expiry' })
    }
    const remaining = session.expiresAt - Date.now()
    if (remaining <= 0) {
      expireNow()
      return
    }

    const timer = window.setTimeout(
      expireNow,
      Math.min(remaining, 2_147_483_647),
    )
    return () => window.clearTimeout(timer)
  }, [requireReauthentication, sessionVersion, status])

  const completeCallback = useCallback(
    async (callbackUrl: string): Promise<string> => {
      setErrorCode(undefined)
      setStatus('authorizing')

      try {
        const transaction = consumeTransaction()
        const state = new URL(callbackUrl).searchParams.get('state') ?? ''
        validateTransaction(transaction, { state })

        const session = await completeAuthorization({
          config,
          callbackUrl,
          transaction,
        })
        setAuthSession(session)
        setRecoveryCorrelation(undefined)
        // A valid callback completes the automatic attempt for this exact
        // transaction and principal before the workspace can challenge again.
        completeReauthenticationMarker({
          state: transaction.state,
          subject: session.claims.sub,
          issuer: session.claims.iss,
        })
        explicitlySignedOutRef.current = false
        redirectInFlightRef.current = null
        applyAccountLocale(session.claims.locale)
        applyAccountTimeZone(session.claims.zoneinfo)
        setClaims(session.claims)
        setEndSessionEndpoint(session.endSessionEndpoint)
        setStatus('authenticated')
        setSessionVersion((version) => version + 1)
        return sanitizeReturnTo(transaction.returnTo)
      } catch (error) {
        const code = errorCodeOf(error, 'exchange_failed')
        setErrorCode(code)
        setStatus('error')
        throw error
      }
    },
    [applyAccountLocale, applyAccountTimeZone, config],
  )

  const expire = useCallback(() => {
    if (getAuthSession()) emitBeforeAuthRedirect()
    closePopupPrompt()
    clearReauthenticationMarker()
    applyAccountLocale(null)
    applyAccountTimeZone(null)
    clearAuthSession()
    setEndSessionEndpoint(undefined)
    setStatus('expired')
  }, [applyAccountLocale, applyAccountTimeZone, closePopupPrompt])

  const logoutLocal = useCallback(() => {
    explicitlySignedOutRef.current = true
    redirectInFlightRef.current = null
    closePopupPrompt()
    emitAuthLogout()
    clearCurrentDrafts()
    clearReauthenticationMarker()
    applyAccountLocale(null)
    applyAccountTimeZone(null)
    clearAuthSession()
    clearTransientPageData()
    setClaims(undefined)
    setEndSessionEndpoint(undefined)
    setErrorCode(undefined)
    setRecoveryCorrelation(undefined)
    setStatus('anonymous')
  }, [applyAccountLocale, applyAccountTimeZone, closePopupPrompt])

  const logoutSso = useCallback((): boolean => {
    const session = getAuthSession()
    const endpoint = session?.endSessionEndpoint
    const idToken = session?.idToken

    explicitlySignedOutRef.current = true
    redirectInFlightRef.current = null
    closePopupPrompt()
    // Clear app state before any provider navigation. The ID token is only
    // used to build the logout URL and is never persisted by the console.
    emitAuthLogout()
    clearCurrentDrafts()
    clearReauthenticationMarker()
    applyAccountLocale(null)
    applyAccountTimeZone(null)
    clearAuthSession()
    clearTransientPageData()
    setClaims(undefined)
    setEndSessionEndpoint(undefined)
    setErrorCode(undefined)
    setRecoveryCorrelation(undefined)

    let url: string | undefined
    if (endpoint && idToken) {
      try {
        url = buildEndSessionUrl({ config, endpoint, idToken })
      } catch {
        url = undefined
      }
    }
    if (!url) {
      setStatus('anonymous')
      return false
    }
    // Keep a neutral progress state until the document is replaced, so the
    // missing-session page never flashes during an intentional sign-out.
    setStatus('signingOut')
    assignDocument(url)
    return true
  }, [applyAccountLocale, applyAccountTimeZone, closePopupPrompt, config])

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      errorCode,
      recoveryCorrelation,
      claims,
      ssoAvailable: Boolean(endSessionEndpoint),
      sessionVersion,
      reauthenticationPopup: popupPrompt,
      signIn,
      requireReauthentication,
      retryReauthentication,
      cancelReauthentication,
      completeCallback,
      expire,
      logoutLocal,
      logoutSso,
      accessToken: peekAccessToken,
    }),
    [
      cancelReauthentication,
      claims,
      completeCallback,
      endSessionEndpoint,
      errorCode,
      expire,
      popupPrompt,
      logoutLocal,
      logoutSso,
      recoveryCorrelation,
      requireReauthentication,
      retryReauthentication,
      sessionVersion,
      signIn,
      status,
    ],
  )

  return (
    <SessionVersionContext.Provider value={sessionVersion}>
      <AuthContext.Provider value={value}>
        {children}
        {popupPrompt ? (
          <ReauthenticationPopup
            prompt={popupPrompt}
            onContinue={continuePopupReauthentication}
            onFallback={fallbackToTopLevelReauthentication}
            onCancel={cancelReauthentication}
          />
        ) : null}
      </AuthContext.Provider>
    </SessionVersionContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}
