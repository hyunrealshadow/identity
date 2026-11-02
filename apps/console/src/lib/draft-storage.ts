import { getAuthSession } from '#/lib/auth/session'

/**
 * Non-sensitive form values survive the interactive step-up redirect. These
 * helpers never store credentials, tokens, or server-issued authorizations.
 *
 * Drafts are scoped by the validated issuer and subject of the current
 * session. An unscoped key from an older console build is intentionally not
 * read; callers must use the same logical key with the current subject.
 */
const STORAGE_PREFIX = 'identity.console.draft.v2'
const ENVELOPE_VERSION = 2
export const DRAFT_TTL_MS = 10 * 60 * 1000

const SENSITIVE_KEY =
  /password|passwd|secret|token|credential|authorization|api[-_]?key|private[-_]?key/i

interface DraftIdentity {
  issuer: string
  subject: string
}

interface DraftEnvelope {
  version: number
  savedAt: number
  issuer: string
  subject: string
  value: unknown
}

function storage(): Storage | null {
  if (typeof window === 'undefined') return null
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

function currentIdentity(): DraftIdentity | null {
  const claims = getAuthSession()?.claims
  const issuer = claims?.iss?.trim()
  const subject = claims?.sub?.trim()
  if (!issuer || !subject) return null
  return { issuer, subject }
}

function scopePrefix(identity: DraftIdentity): string {
  return `${STORAGE_PREFIX}:${encodeURIComponent(identity.issuer)}:${encodeURIComponent(identity.subject)}:`
}

function scopedKey(identity: DraftIdentity, key: string): string {
  return `${scopePrefix(identity)}${encodeURIComponent(key)}`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseEnvelope(
  raw: string,
  identity: DraftIdentity,
): { value: unknown } | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!isRecord(parsed)) return null
  if (parsed.version !== ENVELOPE_VERSION) return null
  if (typeof parsed.savedAt !== 'number' || !Number.isFinite(parsed.savedAt)) {
    return null
  }
  if (parsed.issuer !== identity.issuer || parsed.subject !== identity.subject) {
    return null
  }
  const age = Date.now() - parsed.savedAt
  if (age < 0 || age > DRAFT_TTL_MS) return null
  if (!('value' in parsed)) return null
  return { value: parsed.value }
}

/**
 * Remove secret-looking fields before serialization. Callers should already
 * exclude passwords and tokens, but the storage boundary enforces the rule so
 * an accidental caller cannot persist credential material.
 */
function sanitize(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value instanceof Date) return value.toISOString()
  if (Array.isArray(value)) {
    if (seen.has(value)) return null
    seen.add(value)
    const next = value.map((item) => sanitize(item, seen))
    seen.delete(value)
    return next
  }
  if (isRecord(value)) {
    if (seen.has(value)) return null
    seen.add(value)
    const next: Record<string, unknown> = {}
    for (const [field, child] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(field)) continue
      next[field] = sanitize(child, seen)
    }
    seen.delete(value)
    return next
  }
  return value
}

export function readDraft<T>(key: string): T | null {
  const identity = currentIdentity()
  const store = storage()
  if (!identity || !store) return null

  const storageKey = scopedKey(identity, key)
  try {
    const raw = store.getItem(storageKey)
    if (!raw) return null
    const envelope = parseEnvelope(raw, identity)
    if (!envelope) {
      store.removeItem(storageKey)
      return null
    }
    return envelope.value as T
  } catch {
    return null
  }
}

export function writeDraft(key: string, value: unknown): void {
  const identity = currentIdentity()
  const store = storage()
  if (!identity || !store) return

  try {
    const envelope: DraftEnvelope = {
      version: ENVELOPE_VERSION,
      savedAt: Date.now(),
      issuer: identity.issuer,
      subject: identity.subject,
      value: sanitize(value),
    }
    store.setItem(scopedKey(identity, key), JSON.stringify(envelope))
  } catch {
    // A blocked storage API does not prevent the in-memory form from working.
  }
}

export function clearDraft(key: string): void {
  const identity = currentIdentity()
  const store = storage()
  if (!identity || !store) return

  try {
    store.removeItem(scopedKey(identity, key))
  } catch {
    // Nothing else is required when storage is unavailable.
  }
}

function clearScopedDrafts(identity: DraftIdentity): void {
  const store = storage()
  if (!store) return

  const prefix = scopePrefix(identity)
  try {
    const keys: string[] = []
    for (let index = 0; index < store.length; index += 1) {
      const key = store.key(index)
      if (key?.startsWith(prefix)) keys.push(key)
    }
    for (const key of keys) store.removeItem(key)
  } catch {
    // Logout still proceeds when storage is unavailable.
  }
}

/** Clear drafts even when no form module was loaded in this page lifetime. */
export function clearCurrentDrafts(): void {
  const identity = currentIdentity()
  if (identity) clearScopedDrafts(identity)
}
