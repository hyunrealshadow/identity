import {
  AUTH_TRANSACTION_TTL_MS,
  isSafeReturnTo,
  type StorageLike,
} from '#/lib/auth/transaction'

/**
 * A bounded, non-secret marker for one automatic reauthentication attempt.
 * It survives the full-page OIDC redirect but never contains tokens,
 * credentials, authorization codes or form payloads.
 */
export const REAUTH_MARKER_KEY = 'identity.console.oidc.reauth'
export const REAUTH_MARKER_VERSION = 1
/**
 * A fresh callback followed immediately by the same challenge is treated as a
 * recovery loop. Later freshness expiry is outside this small window and can
 * start a new automatic attempt.
 */
export const REAUTH_LOOP_WINDOW_MS = 30_000

export type ReauthenticationPhase = 'pending' | 'completed'

export type ReauthenticationTrigger =
  'expiry' | 'unauthorized' | 'step_up' | 'policy' | 'manual'

export interface ReauthenticationMarker {
  version: typeof REAUTH_MARKER_VERSION
  phase: ReauthenticationPhase
  subject: string
  issuer: string
  returnTo: string
  state: string
  startedAt: number
  completedAt?: number
  expiresAt: number
}

export interface ReauthenticationIdentity {
  subject: string
  issuer: string
  returnTo: string
}

function browserStorage(): StorageLike | null {
  if (typeof window === 'undefined') return null
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

function optionalStorage(storage?: StorageLike | null): StorageLike | null {
  return storage ?? browserStorage()
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 2048
}

function isMarker(value: unknown): value is ReauthenticationMarker {
  if (typeof value !== 'object' || value === null) return false
  const marker = value as Partial<ReauthenticationMarker>
  if (marker.version !== REAUTH_MARKER_VERSION) return false
  if (marker.phase !== 'pending' && marker.phase !== 'completed') return false
  if (!nonEmptyString(marker.subject) || !nonEmptyString(marker.issuer))
    return false
  if (!nonEmptyString(marker.state)) return false
  if (
    typeof marker.returnTo !== 'string' ||
    marker.returnTo.length > 2048 ||
    !isSafeReturnTo(marker.returnTo)
  ) {
    return false
  }
  if (!Number.isFinite(marker.startedAt) || !Number.isFinite(marker.expiresAt))
    return false
  const startedAt = marker.startedAt as number
  const expiresAt = marker.expiresAt as number
  if (expiresAt <= startedAt) return false
  if (expiresAt - startedAt > AUTH_TRANSACTION_TTL_MS) return false
  if (marker.phase === 'completed') {
    if (!Number.isFinite(marker.completedAt)) return false
    const completedAt = marker.completedAt as number
    if (completedAt < startedAt || completedAt > expiresAt) return false
  } else if (marker.completedAt !== undefined) {
    return false
  }
  return true
}

/**
 * Reads only a valid, unexpired marker. Corrupt or expired data is removed so
 * a stale value can never disable or trigger reauthentication indefinitely.
 */
export function readReauthenticationMarker(
  storage?: StorageLike | null,
  now: number = Date.now(),
): ReauthenticationMarker | null {
  const store = optionalStorage(storage)
  if (!store) return null
  try {
    const raw = store.getItem(REAUTH_MARKER_KEY)
    if (!raw) return null
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      store.removeItem(REAUTH_MARKER_KEY)
      return null
    }
    if (!isMarker(parsed)) {
      store.removeItem(REAUTH_MARKER_KEY)
      return null
    }
    if (now >= parsed.expiresAt) {
      store.removeItem(REAUTH_MARKER_KEY)
      return null
    }
    return parsed
  } catch {
    return null
  }
}

export function saveReauthenticationMarker(
  marker: ReauthenticationMarker,
  storage?: StorageLike | null,
): boolean {
  if (!isMarker(marker)) return false
  const store = optionalStorage(storage)
  if (!store) return false
  try {
    store.setItem(REAUTH_MARKER_KEY, JSON.stringify(marker))
    return true
  } catch {
    return false
  }
}

export function clearReauthenticationMarker(
  storage?: StorageLike | null,
): void {
  const store = optionalStorage(storage)
  if (!store) return
  try {
    store.removeItem(REAUTH_MARKER_KEY)
  } catch {
    // Storage is optional; navigation still proceeds safely.
  }
}

/**
 * Marks the automatic attempt complete only for the transaction and principal
 * that started it. A valid callback therefore records completion before the
 * workspace can issue another challenge.
 */
export function completeReauthenticationMarker(
  expected: { state: string; subject: string; issuer: string },
  storage?: StorageLike | null,
  now: number = Date.now(),
): ReauthenticationMarker | null {
  const marker = readReauthenticationMarker(storage, now)
  if (!marker || marker.phase !== 'pending') return null
  if (marker.state !== expected.state) return null
  if (marker.subject !== expected.subject || marker.issuer !== expected.issuer)
    return null
  if (now > marker.expiresAt) return null
  const completed: ReauthenticationMarker = {
    ...marker,
    phase: 'completed',
    completedAt: now,
  }
  return saveReauthenticationMarker(completed, storage) ? completed : null
}

/**
 * True only for the same principal and return location shortly after a
 * completed automatic callback. An ordinary freshness expiry later is not a
 * loop.
 */
export function isImmediateReauthenticationLoop(
  marker: ReauthenticationMarker | null,
  identity: ReauthenticationIdentity,
  now: number = Date.now(),
): boolean {
  if (!marker || marker.phase !== 'completed') return false
  if (marker.subject !== identity.subject || marker.issuer !== identity.issuer)
    return false
  if (marker.returnTo !== identity.returnTo) return false
  if (marker.completedAt === undefined) return false
  const age = now - marker.completedAt
  return age >= 0 && age <= REAUTH_LOOP_WINDOW_MS
}
