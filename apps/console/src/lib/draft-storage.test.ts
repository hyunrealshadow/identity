import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  clearAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import {
  clearDraft,
  clearCurrentDrafts,
  DRAFT_TTL_MS,
  readDraft,
  writeDraft,
} from '#/lib/draft-storage'

function session(
  subject: string,
  issuer = 'https://identity.example.test',
): AuthSession {
  return {
    accessToken: 'access-token-value',
    idToken: 'id-token-value',
    expiresAt: Date.now() + 60_000,
    scope: 'openid',
    grantedScopes: ['openid'],
    claims: {
      sub: subject,
      iss: issuer,
      aud: 'console',
      exp: Math.floor(Date.now() / 1000) + 60,
    },
  }
}

function storedKeys(): string[] {
  return Array.from({ length: window.sessionStorage.length }, (_, index) =>
    window.sessionStorage.key(index),
  ).filter((key): key is string => key !== null)
}

afterEach(() => {
  clearAuthSession()
  vi.useRealTimers()
})

describe('scoped draft storage', () => {
  it('round-trips a draft for the current validated subject', () => {
    setAuthSession(session('user-a'))

    writeDraft('form', { reason: 'audit' })

    expect(readDraft<{ reason: string }>('form')).toEqual({ reason: 'audit' })
  })

  it('does not read or write without a current subject', () => {
    clearAuthSession()

    writeDraft('form', { reason: 'audit' })

    expect(readDraft('form')).toBeNull()
    expect(window.sessionStorage.length).toBe(0)
  })

  it('isolates drafts by subject', () => {
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'a' })

    setAuthSession(session('user-b'))
    expect(readDraft('form')).toBeNull()
    writeDraft('form', { reason: 'b' })

    setAuthSession(session('user-a'))
    expect(readDraft('form')).toEqual({ reason: 'a' })
  })

  it('isolates drafts by issuer for the same subject', () => {
    setAuthSession(session('shared', 'https://issuer-one.example.test'))
    writeDraft('form', { reason: 'one' })

    setAuthSession(session('shared', 'https://issuer-two.example.test'))
    expect(readDraft('form')).toBeNull()
    writeDraft('form', { reason: 'two' })

    setAuthSession(session('shared', 'https://issuer-one.example.test'))
    expect(readDraft('form')).toEqual({ reason: 'one' })
  })

  it('expires a draft after the bounded lifetime', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-26T00:00:00Z'))
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'audit' })

    vi.setSystemTime(new Date(Date.now() + DRAFT_TTL_MS + 1))
    expect(readDraft('form')).toBeNull()
    expect(window.sessionStorage.length).toBe(0)
  })

  it('rejects invalid JSON and removes the malformed entry', () => {
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'audit' })
    const key = storedKeys()[0]
    window.sessionStorage.setItem(key, '{not-json')

    expect(readDraft('form')).toBeNull()
    expect(window.sessionStorage.getItem(key)).toBeNull()
  })

  it('rejects an envelope issued for another subject', () => {
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'audit' })
    const key = storedKeys()[0]
    const envelope = JSON.parse(window.sessionStorage.getItem(key) ?? '{}')
    window.sessionStorage.setItem(
      key,
      JSON.stringify({ ...envelope, subject: 'user-b' }),
    )

    expect(readDraft('form')).toBeNull()
  })

  it('does not read old unscoped keys', () => {
    setAuthSession(session('user-a'))
    window.sessionStorage.setItem('form', JSON.stringify({ reason: 'legacy' }))

    expect(readDraft('form')).toBeNull()
  })

  it('strips passwords, tokens, and other credentials before persisting', () => {
    setAuthSession(session('user-a'))

    writeDraft('form', {
      username: 'ada',
      password: 'super-secret-password',
      nested: {
        accessToken: 'token-value',
        clientSecret: 'client-secret-value',
        reason: 'audit',
      },
    })

    const raw = window.sessionStorage.getItem(storedKeys()[0]) ?? ''
    expect(raw).not.toContain('super-secret-password')
    expect(raw).not.toContain('token-value')
    expect(raw).not.toContain('client-secret-value')
    expect(readDraft('form')).toEqual({
      username: 'ada',
      nested: { reason: 'audit' },
    })
  })

  it('clears only the current subject draft on explicit discard', () => {
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'a' })

    setAuthSession(session('user-b'))
    writeDraft('form', { reason: 'b' })

    setAuthSession(session('user-a'))
    clearDraft('form')
    expect(readDraft('form')).toBeNull()

    setAuthSession(session('user-b'))
    expect(readDraft('form')).toEqual({ reason: 'b' })
  })

  it('clears only the current subject drafts on explicit logout', () => {
    setAuthSession(session('user-a'))
    writeDraft('form', { reason: 'a' })
    writeDraft('other', { reason: 'a-other' })

    setAuthSession(session('user-b'))
    writeDraft('form', { reason: 'b' })

    setAuthSession(session('user-a'))
    clearCurrentDrafts()
    expect(readDraft('form')).toBeNull()
    expect(readDraft('other')).toBeNull()

    setAuthSession(session('user-b'))
    expect(readDraft('form')).toEqual({ reason: 'b' })
  })
})
