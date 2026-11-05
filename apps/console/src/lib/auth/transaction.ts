import type { Locale } from '#/lib/i18n'

export const AUTH_TRANSACTION_KEY = 'identity.console.oidc.transaction'
export const POPUP_STATE_PREFIX = 'popup.'
export const AUTH_TRANSACTION_TTL_MS = 10 * 60 * 1000

export interface AuthTransaction {
  version: 1
  state: string
  nonce: string
  codeVerifier: string
  locale: Locale
  returnTo: string
  createdAt: number
  expiresAt: number
  acrValues?: string
  maxAge?: number
  /**
   * Identity binding for the subject that started a step-up. A callback that
   * returns a different normalized subject is rejected after token signature
   * validation. This is not a routing hint.
   */
  expectedSubject?: string
}

export type AuthErrorCode =
  | 'missing_transaction'
  | 'expired_transaction'
  | 'invalid_transaction'
  | 'state_mismatch'
  | 'nonce_mismatch'
  | 'issuer_mismatch'
  | 'callback_mismatch'
  | 'discovery_failed'
  | 'exchange_failed'
  | 'authorization_denied'
  | 'authentication_requirements_unmet'
  | 'authorization_failed'
  | 'claims_invalid'
  | 'token_response_invalid'
  | 'missing_end_session'
  | 'reauthentication_loop'

export class AuthError extends Error {
  readonly code: AuthErrorCode

  constructor(code: AuthErrorCode, options?: { cause?: unknown }) {
    super(code, options)
    this.name = 'AuthError'
    this.code = code
  }
}

export interface StorageLike {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

function defaultStorage(): StorageLike {
  return window.sessionStorage
}

export function isSafeReturnTo(value: string): boolean {
  return (
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.includes('\\') &&
    !/[\u0000-\u001f\u007f]/.test(value)
  )
}

function isTransaction(value: unknown): value is AuthTransaction {
  if (typeof value !== 'object' || value === null) return false
  const transaction = value as Partial<AuthTransaction>
  return (
    transaction.version === 1 &&
    typeof transaction.state === 'string' &&
    transaction.state.length > 0 &&
    typeof transaction.nonce === 'string' &&
    transaction.nonce.length > 0 &&
    typeof transaction.codeVerifier === 'string' &&
    transaction.codeVerifier.length > 0 &&
    (transaction.locale === 'en-US' || transaction.locale === 'zh-CN') &&
    typeof transaction.returnTo === 'string' &&
    isSafeReturnTo(transaction.returnTo) &&
    Number.isFinite(transaction.createdAt) &&
    Number.isFinite(transaction.expiresAt) &&
    (transaction.expiresAt as number) > (transaction.createdAt as number) &&
    (transaction.expiresAt as number) - (transaction.createdAt as number) <=
      AUTH_TRANSACTION_TTL_MS &&
    (transaction.acrValues === undefined || typeof transaction.acrValues === 'string') &&
    (transaction.maxAge === undefined ||
      (Number.isInteger(transaction.maxAge) && transaction.maxAge >= 0)) &&
    (transaction.expectedSubject === undefined ||
      (typeof transaction.expectedSubject === 'string' &&
        transaction.expectedSubject.length > 0))
  )
}

export function saveTransaction(
  transaction: AuthTransaction,
  storage: StorageLike = defaultStorage(),
): void {
  if (!isTransaction(transaction)) throw new AuthError('invalid_transaction')
  storage.setItem(AUTH_TRANSACTION_KEY, JSON.stringify(transaction))
}

/**
 * Reads and deletes the transaction before any validation. A failed callback,
 * token exchange or navigation can therefore not reuse the same state, nonce
 * or PKCE verifier.
 */
export function consumeTransaction(
  storage: StorageLike = defaultStorage(),
  now: number = Date.now(),
): AuthTransaction {
  const raw = storage.getItem(AUTH_TRANSACTION_KEY)
  if (raw === null) throw new AuthError('missing_transaction')
  storage.removeItem(AUTH_TRANSACTION_KEY)
  if (!raw) throw new AuthError('invalid_transaction')

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    throw new AuthError('invalid_transaction', { cause: error })
  }

  if (!isTransaction(parsed)) throw new AuthError('invalid_transaction')
  if (now >= parsed.expiresAt) throw new AuthError('expired_transaction')
  return parsed
}

export function clearTransaction(storage: StorageLike = defaultStorage()): void {
  storage.removeItem(AUTH_TRANSACTION_KEY)
}

export function validateTransaction(
  transaction: AuthTransaction,
  expected: { state: string; nonce?: string },
  now: number = Date.now(),
): void {
  if (now >= transaction.expiresAt) throw new AuthError('expired_transaction')
  if (transaction.state !== expected.state) throw new AuthError('state_mismatch')
  if (expected.nonce !== undefined && transaction.nonce !== expected.nonce) {
    throw new AuthError('nonce_mismatch')
  }
}

export function buildTransaction(input: {
  state: string
  nonce: string
  codeVerifier: string
  locale: Locale
  returnTo: string
  now?: number
  acrValues?: string
  maxAge?: number
  expectedSubject?: string
}): AuthTransaction {
  const createdAt = input.now ?? Date.now()
  const transaction: AuthTransaction = {
    version: 1,
    state: input.state,
    nonce: input.nonce,
    codeVerifier: input.codeVerifier,
    locale: input.locale,
    returnTo: input.returnTo,
    createdAt,
    expiresAt: createdAt + AUTH_TRANSACTION_TTL_MS,
  }
  if (input.acrValues) transaction.acrValues = input.acrValues
  if (input.maxAge !== undefined) transaction.maxAge = input.maxAge
  if (input.expectedSubject !== undefined) {
    transaction.expectedSubject = input.expectedSubject
  }
  return transaction
}
