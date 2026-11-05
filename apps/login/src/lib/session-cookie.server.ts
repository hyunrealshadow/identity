import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { deleteCookie, getCookie, setCookie } from '@tanstack/react-start/server'

const IV_LENGTH = 12
const TAG_LENGTH = 16

export interface SessionCookieConfig {
  name: string
  /** Hex-encoded 32-byte key derived from the deployment session secret. */
  password: string
  maxAge: number
}

export interface SessionCookie<T> {
  data: T
  update(value: Partial<T>): void
  clear(): void
}

function key(password: string): Buffer {
  const value = Buffer.from(password, 'hex')
  if (value.length !== 32) throw new Error('session password must be 32 bytes')
  return value
}

function seal(value: unknown, password: string): string {
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', key(password), iv)
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(value), 'utf8')),
    cipher.final(),
  ])
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url')
}

function unseal<T>(token: string, password: string): T | null {
  try {
    const raw = Buffer.from(token, 'base64url')
    if (raw.length <= IV_LENGTH + TAG_LENGTH) return null
    const iv = raw.subarray(0, IV_LENGTH)
    const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH)
    const decipher = createDecipheriv('aes-256-gcm', key(password), iv)
    decipher.setAuthTag(tag)
    const plaintext = Buffer.concat([
      decipher.update(raw.subarray(IV_LENGTH + TAG_LENGTH)),
      decipher.final(),
    ])
    return JSON.parse(plaintext.toString('utf8')) as T
  } catch {
    // An unreadable or tampered cookie is treated as absent: the request
    // continues unauthenticated instead of failing or trusting its content.
    return null
  }
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const,
    path: '/',
    maxAge,
  }
}

/**
 * Encrypted, authenticated session cookie built on the request/response
 * helpers of TanStack Start. The payload is never readable or forgeable by the
 * browser, and separate cookie names use independently derived keys.
 */
export function createSessionCookie<T extends object>({
  name,
  password,
  maxAge,
}: SessionCookieConfig): SessionCookie<T> {
  const stored = getCookie(name)
  const decoded = stored ? unseal<T>(stored, password) : null
  const data = (decoded ?? {}) as T

  return {
    data,
    update(value) {
      // Keep the in-request view in sync with what a later read would decode.
      Object.assign(data, value)
      setCookie(
        name,
        seal({ ...data, ...value }, password),
        cookieOptions(maxAge),
      )
    },
    clear() {
      deleteCookie(name, cookieOptions(maxAge))
    },
  }
}
