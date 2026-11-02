import { describe, expect, it } from 'vitest'

import {
  AUTH_TRANSACTION_KEY,
  AUTH_TRANSACTION_TTL_MS,
  AuthError,
  buildTransaction,
  consumeTransaction,
  saveTransaction,
  validateTransaction,
  type StorageLike,
} from './transaction'

class MemoryStorage implements StorageLike {
  private readonly values = new Map<string, string>()

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value)
  }

  removeItem(key: string): void {
    this.values.delete(key)
  }
}

function expectCode(run: () => unknown, code: string) {
  try {
    run()
  } catch (error) {
    expect(error).toMatchObject({ code })
    return
  }
  throw new Error(`Expected AuthError code ${code}`)
}

function transaction(now = 1_000) {
  return buildTransaction({
    state: 'state-value',
    nonce: 'nonce-value',
    codeVerifier: 'verifier-value',
    locale: 'en-US',
    returnTo: '/account/profile?x=1',
    now,
  })
}

describe('authorization transaction', () => {
  it('is single-use: reading deletes it before validation', () => {
    const storage = new MemoryStorage()
    saveTransaction(transaction(), storage)

    const consumed = consumeTransaction(storage, 2_000)
    expect(consumed.state).toBe('state-value')
    expect(storage.getItem(AUTH_TRANSACTION_KEY)).toBeNull()

    expectCode(() => consumeTransaction(storage, 2_000), 'missing_transaction')
  })

  it('rejects an expired transaction and still removes it', () => {
    const storage = new MemoryStorage()
    saveTransaction(transaction(1_000), storage)

    expectCode(
      () => consumeTransaction(storage, 1_000 + AUTH_TRANSACTION_TTL_MS),
      'expired_transaction',
    )
    expect(storage.getItem(AUTH_TRANSACTION_KEY)).toBeNull()
  })

  it('rejects state and nonce mismatches', () => {
    const value = transaction()

    expectCode(
      () => validateTransaction(value, { state: 'different' }, 2_000),
      'state_mismatch',
    )

    expectCode(
      () =>
        validateTransaction(
          value,
          { state: 'state-value', nonce: 'different' },
          2_000,
        ),
      'nonce_mismatch',
    )

    expect(() =>
      validateTransaction(value, { state: 'state-value', nonce: 'nonce-value' }, 2_000),
    ).not.toThrow()
  })

  it('retains an optional expected subject binding through storage', () => {
    const storage = new MemoryStorage()
    const bound = buildTransaction({
      state: 'state-value',
      nonce: 'nonce-value',
      codeVerifier: 'verifier-value',
      locale: 'en-US',
      returnTo: '/',
      expectedSubject: 'user-a',
      now: 1_000,
    })

    saveTransaction(bound, storage)
    expect(consumeTransaction(storage, 2_000).expectedSubject).toBe('user-a')
  })

  it('rejects a present but empty expected subject before storing it', () => {
    const storage = new MemoryStorage()
    const invalid = buildTransaction({
      state: 'state-value',
      nonce: 'nonce-value',
      codeVerifier: 'verifier-value',
      locale: 'en-US',
      returnTo: '/',
      expectedSubject: '',
      now: 1_000,
    })

    expectCode(() => saveTransaction(invalid, storage), 'invalid_transaction')
    expect(storage.getItem(AUTH_TRANSACTION_KEY)).toBeNull()
  })

  it('rejects an unsafe returnTo before storing it', () => {
    const storage = new MemoryStorage()
    const unsafe = buildTransaction({
      state: 'state',
      nonce: 'nonce',
      codeVerifier: 'verifier',
      locale: 'en-US',
      returnTo: '//evil.example',
      now: 1_000,
    })

    expect(() => saveTransaction(unsafe, storage)).toThrow(AuthError)
    expect(storage.getItem(AUTH_TRANSACTION_KEY)).toBeNull()
  })

  it('rejects malformed stored JSON without retaining it', () => {
    const storage = new MemoryStorage()
    storage.setItem(AUTH_TRANSACTION_KEY, '{not-json')

    expectCode(() => consumeTransaction(storage, 2_000), 'invalid_transaction')
    expect(storage.getItem(AUTH_TRANSACTION_KEY)).toBeNull()
  })
})
