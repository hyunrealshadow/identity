import { describe, expect, it, vi } from 'vitest'

import {
  POPUP_CALLBACK_MESSAGE_TYPE,
  PopupCallbackGuard,
  callbackMatchesRedirect,
  isPopupCallback,
  openAuthenticationPopup,
  popupWindowRect,
  postCallbackToOpener,
  verifyPopupCallback,
  type VerifyPopupCallbackInput,
} from './popup-reauthentication'
import { buildTransaction } from './transaction'

const REDIRECT_URI = 'https://console.example.test/callback'
const CALLBACK_ORIGIN = 'https://console.example.test'
const NOW = 1_000_000

const source = { name: 'owned-popup' } as unknown as Window

function transaction() {
  return buildTransaction({
    state: 'state-a',
    nonce: 'nonce-a',
    codeVerifier: 'verifier-a',
    locale: 'en-US',
    returnTo: '/users',
    now: NOW,
    expectedSubject: 'user-a',
  })
}

function message(
  state = 'state-a',
  callbackUrl = `${REDIRECT_URI}?state=${state}&code=code-a`,
) {
  return {
    type: POPUP_CALLBACK_MESSAGE_TYPE,
    callbackUrl,
    state,
  }
}

function input(
  overrides: Partial<VerifyPopupCallbackInput> = {},
): VerifyPopupCallbackInput {
  const value = transaction()
  return {
    event: {
      origin: CALLBACK_ORIGIN,
      source,
      data: message(),
    },
    expectedOrigin: CALLBACK_ORIGIN,
    expectedSource: source,
    redirectUri: REDIRECT_URI,
    transaction: value,
    now: NOW + 1_000,
    ...overrides,
  }
}

describe('popup callback message', () => {
  it('accepts the exact origin, source, state, callback path and unexpired transaction', () => {
    expect(verifyPopupCallback(input())).toMatchObject({
      ok: true,
      state: 'state-a',
    })
  })

  it('rejects a message from a different origin', () => {
    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: 'https://attacker.example.test',
            source,
            data: message(),
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'origin_mismatch' })
  })

  it('rejects a message from a window the parent does not own', () => {
    const other = {} as unknown as Window
    expect(
      verifyPopupCallback(
        input({
          event: { origin: CALLBACK_ORIGIN, source: other, data: message() },
        }),
      ),
    ).toEqual({ ok: false, reason: 'source_mismatch' })
    expect(verifyPopupCallback(input({ expectedSource: null }))).toEqual({
      ok: false,
      reason: 'source_mismatch',
    })
  })

  it('rejects a state that does not match the retained transaction', () => {
    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: CALLBACK_ORIGIN,
            source,
            data: message('state-b'),
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'state_mismatch' })
  })

  it('rejects a callback on a different origin or path', () => {
    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: CALLBACK_ORIGIN,
            source,
            data: message(
              'state-a',
              'https://attacker.example.test/callback?state=state-a',
            ),
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'callback_mismatch' })

    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: CALLBACK_ORIGIN,
            source,
            data: message('state-a', `${CALLBACK_ORIGIN}/other?state=state-a`),
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'callback_mismatch' })
  })

  it('rejects an expired transaction and a missing transaction', () => {
    const value = transaction()
    expect(
      verifyPopupCallback(
        input({
          transaction: value,
          now: value.expiresAt,
        }),
      ),
    ).toEqual({ ok: false, reason: 'transaction_expired' })
    expect(verifyPopupCallback(input({ transaction: null }))).toEqual({
      ok: false,
      reason: 'transaction_missing',
    })
  })

  it('rejects malformed, token-bearing and mismatched messages', () => {
    expect(
      verifyPopupCallback(
        input({
          event: { origin: CALLBACK_ORIGIN, source, data: { type: 'other' } },
        }),
      ),
    ).toEqual({ ok: false, reason: 'message_invalid' })

    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: CALLBACK_ORIGIN,
            source,
            data: {
              type: POPUP_CALLBACK_MESSAGE_TYPE,
              callbackUrl: `${REDIRECT_URI}?state=state-a&code=code-a`,
              state: 'state-b',
            },
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'message_invalid' })

    expect(
      verifyPopupCallback(
        input({
          event: {
            origin: CALLBACK_ORIGIN,
            source,
            data: {
              type: POPUP_CALLBACK_MESSAGE_TYPE,
              callbackUrl: 'javascript:alert(1)',
              state: 'state-a',
            },
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'message_invalid' })
  })

  it('consumes a transaction once and ignores duplicate deliveries', () => {
    const guard = new PopupCallbackGuard()
    expect(guard.accept(input()).ok).toBe(true)
    expect(guard.accept(input())).toEqual({
      ok: false,
      reason: 'already_consumed',
    })
  })

  it('does not consume the transaction on rejected messages', () => {
    const guard = new PopupCallbackGuard()
    expect(
      guard.accept(
        input({
          event: {
            origin: 'https://attacker.example.test',
            source,
            data: message(),
          },
        }),
      ),
    ).toEqual({ ok: false, reason: 'origin_mismatch' })
    expect(guard.accept(input()).ok).toBe(true)
  })
})

describe('popup window', () => {
  it('fits a popup inside a small screen with a nonzero origin', () => {
    expect(
      popupWindowRect({
        availWidth: 400,
        availHeight: 300,
        availLeft: 10,
        availTop: 20,
      }),
    ).toEqual({ width: 400, height: 300, left: 10, top: 20 })
  })

  it('returns null when the browser blocks the popup', () => {
    const open = vi.fn().mockReturnValue(null)
    const win = { open } as unknown as Window
    expect(openAuthenticationPopup({ win })).toBeNull()
    expect(open).toHaveBeenCalledTimes(1)
  })
})

describe('callback helpers', () => {
  it('matches only the configured callback origin and path', () => {
    expect(
      callbackMatchesRedirect(`${REDIRECT_URI}?state=a`, REDIRECT_URI),
    ).toBe(true)
    expect(
      callbackMatchesRedirect(`${REDIRECT_URI}/extra?state=a`, REDIRECT_URI),
    ).toBe(false)
    expect(
      callbackMatchesRedirect(
        'https://attacker.example.test/callback?state=a',
        REDIRECT_URI,
      ),
    ).toBe(false)
  })

  it('posts only the callback URL and state to the exact console origin', () => {
    const postMessage = vi.fn()
    const opener = { postMessage } as unknown as Window
    const current = {
      opener,
      location: {
        href: 'https://console.example.test/callback?state=state-a&code=code-a',
        origin: 'https://console.example.test',
      },
    } as unknown as Window

    expect(
      postCallbackToOpener({
        currentWindow: current,
        targetOrigin: CALLBACK_ORIGIN,
      }),
    ).toBe(true)
    expect(postMessage).toHaveBeenCalledTimes(1)
    const [data, targetOrigin] = postMessage.mock.calls[0]
    expect(targetOrigin).toBe(CALLBACK_ORIGIN)
    expect(data).toEqual({
      type: POPUP_CALLBACK_MESSAGE_TYPE,
      callbackUrl:
        'https://console.example.test/callback?state=state-a&code=code-a',
      state: 'state-a',
    })
  })

  it('refuses a callback without an opener or with a non-http target', () => {
    const current = {
      opener: null,
      location: {
        href: 'https://console.example.test/callback?state=state-a',
        origin: 'https://console.example.test',
      },
    } as unknown as Window
    expect(
      postCallbackToOpener({
        currentWindow: current,
        targetOrigin: CALLBACK_ORIGIN,
      }),
    ).toBe(false)

    const opener = { postMessage: vi.fn() } as unknown as Window
    expect(
      postCallbackToOpener({
        currentWindow: { ...current, opener } as unknown as Window,
        targetOrigin: 'not-a-url',
      }),
    ).toBe(false)
  })

  it('detects a callback opened in another window', () => {
    const standalone = {} as { opener?: unknown }
    expect(isPopupCallback(standalone as unknown as Window)).toBe(false)

    const opened = {
      location: { href: `${REDIRECT_URI}?state=popup.pending` },
    } as { opener?: unknown; location: { href: string } }
    opened.opener = {}
    expect(isPopupCallback(opened as unknown as Window)).toBe(true)
    opened.location.href = `${REDIRECT_URI}?state=ordinary-login`
    expect(isPopupCallback(opened as unknown as Window)).toBe(false)

    const self = {} as { opener?: unknown }
    self.opener = self
    expect(isPopupCallback(self as unknown as Window)).toBe(false)
    expect(isPopupCallback(undefined)).toBe(false)
  })
})
