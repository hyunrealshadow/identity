import type { StepUpRequest } from '#/lib/auth/oidc'
import type { ReauthenticationTrigger } from '#/lib/auth/reauthentication'
import type { AuthErrorCode, AuthTransaction } from '#/lib/auth/transaction'
import { POPUP_STATE_PREFIX } from '#/lib/auth/transaction'

/**
 * The popup callback only forwards the callback URL and its state to the
 * window that opened it. The authorization code remains inside that URL;
 * tokens, verifiers and other credentials never cross the message boundary.
 */
export const POPUP_CALLBACK_MESSAGE_TYPE = 'identity.console.popup-callback'
export const POPUP_WINDOW_NAME_PREFIX = 'identity-console-reauth'
export const POPUP_WIDTH = 520
export const POPUP_HEIGHT = 720
/** How often the parent checks whether the user closed the popup. */
export const POPUP_CLOSED_POLL_MS = 500
const MAX_CALLBACK_URL_LENGTH = 8192

export interface PopupCallbackMessage {
  type: typeof POPUP_CALLBACK_MESSAGE_TYPE
  callbackUrl: string
  state: string
}

export type PopupReauthenticationPhase =
  | 'starting'
  | 'waiting'
  | 'completing'
  | 'failed'
  | 'blocked'

/**
 * The parent owns this prompt for the lifetime of one popup attempt. The
 * transaction is retained in memory and is dropped when the popup closes;
 * the popup never reads, consumes or exchanges it.
 */
export interface PopupReauthenticationPrompt {
  phase: PopupReauthenticationPhase
  returnTo: string
  reason: ReauthenticationTrigger
  challenge?: StepUpRequest
  requestId?: string
  traceId?: string
  authorizeUrl?: string
  transaction?: AuthTransaction
  subject?: string
  issuer?: string
  errorCode?: AuthErrorCode
}

export type PopupCallbackRejection =
  | 'already_consumed'
  | 'source_mismatch'
  | 'origin_mismatch'
  | 'message_invalid'
  | 'transaction_missing'
  | 'transaction_expired'
  | 'state_mismatch'
  | 'callback_mismatch'

export interface PopupCallbackAccepted {
  ok: true
  callbackUrl: string
  state: string
}

export interface PopupCallbackRejected {
  ok: false
  reason: PopupCallbackRejection
}

export type PopupCallbackResult = PopupCallbackAccepted | PopupCallbackRejected

export interface PopupCallbackEvent {
  origin: string
  source: unknown
  data: unknown
}

export interface VerifyPopupCallbackInput {
  event: PopupCallbackEvent
  expectedOrigin: string
  expectedSource: unknown | null
  redirectUri: string
  transaction: Pick<AuthTransaction, 'state' | 'expiresAt'> | null
  now?: number
}

export interface PopupWindowRect {
  width: number
  height: number
  left: number
  top: number
}

type AvailableScreen = Pick<Screen, 'availWidth' | 'availHeight'> & {
  availLeft?: number
  availTop?: number
}

function finite(value: number | undefined): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/**
 * Centers a 520x720 CSS-pixel window and clamps it to the available screen.
 */
export function popupWindowRect(
  screenLike:
    | AvailableScreen
    | undefined = typeof window === 'undefined' ? undefined : window.screen,
): PopupWindowRect {
  const availableWidth = finite(screenLike?.availWidth) ?? POPUP_WIDTH
  const availableHeight = finite(screenLike?.availHeight) ?? POPUP_HEIGHT
  const availableLeft = finite(screenLike?.availLeft) ?? 0
  const availableTop = finite(screenLike?.availTop) ?? 0
  const width = Math.max(1, Math.min(POPUP_WIDTH, Math.floor(availableWidth)))
  const height = Math.max(1, Math.min(POPUP_HEIGHT, Math.floor(availableHeight)))
  const left = Math.max(
    0,
    Math.round(availableLeft + (availableWidth - width) / 2),
  )
  const top = Math.max(
    0,
    Math.round(availableTop + (availableHeight - height) / 2),
  )
  return { width, height, left, top }
}

export function popupWindowFeatures(rect: PopupWindowRect): string {
  return [
    'popup=yes',
    'resizable=yes',
    'scrollbars=yes',
    `width=${rect.width}`,
    `height=${rect.height}`,
    `left=${rect.left}`,
    `top=${rect.top}`,
  ].join(',')
}

export function popupWindowName(attempt: number): string {
  return `${POPUP_WINDOW_NAME_PREFIX}-${crypto.randomUUID()}-${Math.max(0, Math.floor(attempt))}`
}

/**
 * Reserves a blank browser popup synchronously. Callers must invoke this from
 * the user gesture (or automatic attempt) itself, before discovery or any
 * other await, so a popup blocker can accept the window.
 */
export function openAuthenticationPopup(options?: {
  name?: string
  title?: string
  win?: Window
  screen?: AvailableScreen
}): Window | null {
  const win = options?.win ?? (typeof window === 'undefined' ? undefined : window)
  if (!win) return null

  let popup: Window | null
  try {
    popup = win.open(
      'about:blank',
      options?.name ?? POPUP_WINDOW_NAME_PREFIX,
      popupWindowFeatures(popupWindowRect(options?.screen ?? win.screen)),
    )
  } catch {
    return null
  }
  if (!popup) return null

  if (options?.title) {
    try {
      popup.document.title = options.title
    } catch {
      // A browser may refuse to touch the blank document; navigation still works.
    }
  }
  return popup
}

export function closeAuthenticationPopup(
  popup: Window | null | undefined,
): void {
  if (!popup) return
  try {
    if (!popup.closed) popup.close()
  } catch {
    // A closed or inaccessible popup needs no further cleanup.
  }
}

export function isPopupCallback(
  win: Window | undefined = typeof window === 'undefined' ? undefined : window,
): boolean {
  if (!win?.opener || win.opener === win) return false
  try {
    return new URL(win.location.href).searchParams.get('state')?.startsWith(POPUP_STATE_PREFIX) === true
  } catch {
    return false
  }
}

function parseCallbackMessage(data: unknown): PopupCallbackMessage | null {
  if (typeof data !== 'object' || data === null) return null
  const record = data as Record<string, unknown>
  if (record.type !== POPUP_CALLBACK_MESSAGE_TYPE) return null
  if (
    typeof record.callbackUrl !== 'string' ||
    record.callbackUrl.length > MAX_CALLBACK_URL_LENGTH
  ) {
    return null
  }
  if (
    typeof record.state !== 'string' ||
    record.state.length === 0 ||
    record.state.length > 2048
  ) {
    return null
  }

  let callback: URL
  try {
    callback = new URL(record.callbackUrl)
  } catch {
    return null
  }
  if (callback.protocol !== 'http:' && callback.protocol !== 'https:')
    return null
  if (callback.username || callback.password) return null
  // The forwarded state is a routing value, not proof. It must agree with the
  // callback URL so the parent never validates one value while using another.
  if ((callback.searchParams.get('state') ?? '') !== record.state) return null

  return {
    type: POPUP_CALLBACK_MESSAGE_TYPE,
    callbackUrl: record.callbackUrl,
    state: record.state,
  }
}

export function callbackMatchesRedirect(
  callbackUrl: string,
  redirectUri: string,
): boolean {
  let callback: URL
  let redirect: URL
  try {
    callback = new URL(callbackUrl)
    redirect = new URL(redirectUri)
  } catch {
    return false
  }
  if (callback.username || callback.password) return false
  return (
    callback.origin === redirect.origin &&
    callback.pathname === redirect.pathname
  )
}

/**
 * Accepts only a message from the owned popup window, from the configured
 * console callback origin, for the exact callback path, carrying the expected
 * state and an unexpired transaction. The subject binding is additionally
 * enforced by completeAuthorization using the transaction's expectedSubject.
 */
export function verifyPopupCallback(
  input: VerifyPopupCallbackInput,
): PopupCallbackResult {
  if (!input.expectedSource || input.event.source !== input.expectedSource) {
    return { ok: false, reason: 'source_mismatch' }
  }
  if (input.event.origin !== input.expectedOrigin) {
    return { ok: false, reason: 'origin_mismatch' }
  }

  const message = parseCallbackMessage(input.event.data)
  if (!message) return { ok: false, reason: 'message_invalid' }

  if (!input.transaction) return { ok: false, reason: 'transaction_missing' }
  const now = input.now ?? Date.now()
  if (now >= input.transaction.expiresAt) {
    return { ok: false, reason: 'transaction_expired' }
  }
  if (message.state !== input.transaction.state) {
    return { ok: false, reason: 'state_mismatch' }
  }
  if (!callbackMatchesRedirect(message.callbackUrl, input.redirectUri)) {
    return { ok: false, reason: 'callback_mismatch' }
  }

  return { ok: true, callbackUrl: message.callbackUrl, state: message.state }
}

/**
 * A transaction can be used once. Rejections do not consume it, so an
 * untrusted probe cannot prevent the real callback from arriving.
 */
export class PopupCallbackGuard {
  private consumed = false

  accept(input: VerifyPopupCallbackInput): PopupCallbackResult {
    if (this.consumed) return { ok: false, reason: 'already_consumed' }
    const result = verifyPopupCallback(input)
    if (result.ok) this.consumed = true
    return result
  }
}

/**
 * Called by the callback route when it runs in the popup. It posts only the
 * callback URL and state to the exact console origin; it never reads or
 * exchanges the authorization code and never touches the parent transaction.
 */
export function postCallbackToOpener(options?: {
  currentWindow?: Window
  targetOrigin?: string
}): boolean {
  const current =
    options?.currentWindow ??
    (typeof window === 'undefined' ? undefined : window)
  if (!current) return false

  const opener = current.opener
  if (!opener || opener === current) return false

  let targetOrigin: string
  try {
    targetOrigin = new URL(
      options?.targetOrigin ?? current.location.origin,
    ).origin
  } catch {
    return false
  }
  if (targetOrigin === 'null') return false

  let callbackUrl: string
  try {
    callbackUrl = current.location.href
  } catch {
    return false
  }

  let state: string
  try {
    state = new URL(callbackUrl).searchParams.get('state') ?? ''
  } catch {
    return false
  }

  if (!state || callbackUrl.length > MAX_CALLBACK_URL_LENGTH) return false

  const message: PopupCallbackMessage = {
    type: POPUP_CALLBACK_MESSAGE_TYPE,
    callbackUrl,
    state,
  }

  try {
    opener.postMessage(message, targetOrigin)
    return true
  } catch {
    return false
  }
}
