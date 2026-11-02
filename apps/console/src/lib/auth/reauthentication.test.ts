import { describe, expect, it } from 'vitest'

import {
  AUTH_TRANSACTION_TTL_MS,
  type StorageLike,
} from '#/lib/auth/transaction'
import {
  REAUTH_LOOP_WINDOW_MS,
  REAUTH_MARKER_KEY,
  clearReauthenticationMarker,
  completeReauthenticationMarker,
  isImmediateReauthenticationLoop,
  readReauthenticationMarker,
  saveReauthenticationMarker,
  type ReauthenticationMarker,
} from './reauthentication'

class MemoryStorage implements StorageLike {
  readonly values = new Map<string, string>()

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

const NOW = 1_000_000

function marker(
  overrides: Partial<ReauthenticationMarker> = {},
): ReauthenticationMarker {
  const base: ReauthenticationMarker = {
    version: 1,
    phase: 'pending',
    subject: 'user-a',
    issuer: 'https://issuer.example.test',
    returnTo: '/users?filter=a#top',
    state: 'state-a',
    startedAt: NOW - 1_000,
    expiresAt: NOW - 1_000 + AUTH_TRANSACTION_TTL_MS,
  }
  return { ...base, ...overrides }
}

function identity(
  overrides: Partial<{
    subject: string
    issuer: string
    returnTo: string
  }> = {},
) {
  return {
    subject: 'user-a',
    issuer: 'https://issuer.example.test',
    returnTo: '/users?filter=a#top',
    ...overrides,
  }
}

describe('automatic reauthentication marker', () => {
  it('round-trips a bounded marker and removes malformed or expired values', () => {
    const storage = new MemoryStorage()
    expect(saveReauthenticationMarker(marker(), storage)).toBe(true)
    expect(readReauthenticationMarker(storage, NOW)).toMatchObject({
      subject: 'user-a',
      state: 'state-a',
      phase: 'pending',
    })

    storage.setItem(REAUTH_MARKER_KEY, '{not-json')
    expect(readReauthenticationMarker(storage, NOW)).toBeNull()
    expect(storage.getItem(REAUTH_MARKER_KEY)).toBeNull()

    saveReauthenticationMarker(marker(), storage)
    expect(
      readReauthenticationMarker(
        storage,
        NOW - 1_000 + AUTH_TRANSACTION_TTL_MS,
      ),
    ).toBeNull()
    expect(storage.getItem(REAUTH_MARKER_KEY)).toBeNull()

    storage.setItem(
      REAUTH_MARKER_KEY,
      JSON.stringify(marker({ expiresAt: NOW + AUTH_TRANSACTION_TTL_MS + 1 })),
    )
    expect(readReauthenticationMarker(storage, NOW)).toBeNull()
  })

  it('marks completion only for the matching transaction and principal', () => {
    const storage = new MemoryStorage()
    saveReauthenticationMarker(marker(), storage)

    expect(
      completeReauthenticationMarker(
        {
          state: 'different',
          subject: 'user-a',
          issuer: 'https://issuer.example.test',
        },
        storage,
        NOW,
      ),
    ).toBeNull()
    expect(
      completeReauthenticationMarker(
        {
          state: 'state-a',
          subject: 'user-b',
          issuer: 'https://issuer.example.test',
        },
        storage,
        NOW,
      ),
    ).toBeNull()

    const completed = completeReauthenticationMarker(
      {
        state: 'state-a',
        subject: 'user-a',
        issuer: 'https://issuer.example.test',
      },
      storage,
      NOW,
    )
    expect(completed?.phase).toBe('completed')
    expect(completed?.completedAt).toBe(NOW)
  })

  it('detects only an immediate completed loop for the same return location', () => {
    const completed = marker({ phase: 'completed', completedAt: NOW })

    expect(
      isImmediateReauthenticationLoop(completed, identity(), NOW + 1_000),
    ).toBe(true)
    expect(
      isImmediateReauthenticationLoop(
        completed,
        identity(),
        NOW + REAUTH_LOOP_WINDOW_MS + 1,
      ),
    ).toBe(false)
    expect(
      isImmediateReauthenticationLoop(
        completed,
        identity({ returnTo: '/groups' }),
        NOW + 1_000,
      ),
    ).toBe(false)
    expect(
      isImmediateReauthenticationLoop(
        completed,
        identity({ subject: 'user-b' }),
        NOW + 1_000,
      ),
    ).toBe(false)
  })

  it('clears markers safely even when storage is unavailable', () => {
    const throwing: StorageLike = {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('blocked')
      },
      removeItem: () => {
        throw new Error('blocked')
      },
    }

    expect(() => clearReauthenticationMarker(throwing)).not.toThrow()
    expect(() => saveReauthenticationMarker(marker(), throwing)).not.toThrow()
    expect(readReauthenticationMarker(throwing, NOW)).toBeNull()
  })
})
