/**
 * Client-safe contracts for a popup account-center reauthentication.
 *
 * Only the authorization address and its opaque state cross into the browser.
 * Tokens, credentials, authorization codes, and verifiers stay in the server
 * session and are never part of the popup message.
 */
export interface AccountReauthRequest {
  url: string
  state: string
}

export const ACCOUNT_REAUTH_MESSAGE_TYPE = 'identity.account-reauth'

export type AccountReauthResult = 'success' | 'error' | 'cancelled'

export interface AccountReauthMessage {
  type: typeof ACCOUNT_REAUTH_MESSAGE_TYPE
  state: string
  returnTo: string
  result: AccountReauthResult
}

export function isAccountReauthMessage(
  value: unknown,
): value is AccountReauthMessage {
  if (!value || typeof value !== 'object') return false
  const message = value as Partial<AccountReauthMessage>
  return (
    message.type === ACCOUNT_REAUTH_MESSAGE_TYPE &&
    typeof message.state === 'string' &&
    message.state.length > 0 &&
    typeof message.returnTo === 'string' &&
    (message.result === 'success' ||
      message.result === 'error' ||
      message.result === 'cancelled')
  )
}

/** Only same-origin account paths may be resumed after popup auth. */
export function safeAccountReauthReturnTo(value: unknown) {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.startsWith('//')
  ) {
    return undefined
  }
  try {
    const url = new URL(value, 'https://identity.invalid')
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return undefined
  }
}

/**
 * Verify a candidate message before acting on it. The exact sender origin and
 * the exact popup window must match, and the state binds the message to the
 * request that opened this popup.
 */
export function verifyAccountReauthMessage(options: {
  data: unknown
  origin: string
  expectedOrigin: string
  source: MessageEventSource | null
  expectedSource: MessageEventSource | null
  expectedState: string
}): AccountReauthMessage | undefined {
  if (options.origin !== options.expectedOrigin) return
  if (!options.expectedSource || options.source !== options.expectedSource)
    return
  if (!isAccountReauthMessage(options.data)) return
  if (options.data.state !== options.expectedState) return
  return options.data
}

/** Open during the user gesture; the server authorization URL is assigned later. */
export function openAccountReauthPopup(owner: Window = window): Window | null {
  const screen = owner.screen as Screen & { availLeft?: number; availTop?: number }
  const width = Math.max(320, Math.min(520, screen.availWidth - 24))
  const height = Math.max(400, Math.min(720, screen.availHeight - 48))
  const minLeft = screen.availLeft ?? owner.screenX
  const minTop = screen.availTop ?? owner.screenY
  const left = Math.round(Math.max(minLeft, Math.min(owner.screenX + (owner.outerWidth - width) / 2, minLeft + screen.availWidth - width)))
  const top = Math.round(Math.max(minTop, Math.min(owner.screenY + (owner.outerHeight - height) / 2, minTop + screen.availHeight - height)))
  try {
    return owner.open('about:blank', '_blank', `popup=yes,width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`)
  } catch {
    return null
  }
}
