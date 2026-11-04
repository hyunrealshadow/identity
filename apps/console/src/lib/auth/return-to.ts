import { BASE_HREF, isWithinBasePath } from '#/lib/base-path'

const FALLBACK = BASE_HREF

function defaultOrigin(): string {
  return typeof window === 'undefined' ? 'http://localhost' : window.location.origin
}

/**
 * Accept only a same-origin path. Absolute same-origin http(s) URLs are
 * reduced to path/search/hash. Foreign origins, protocol-relative paths,
 * backslashes, credentials, control characters and non-http schemes are
 * rejected. A rejected value falls back to the Console base path and never
 * leaves the application's deployment prefix.
 */
export function sanitizeReturnTo(
  value: unknown,
  currentOrigin: string = defaultOrigin(),
  fallback: string = FALLBACK,
): string {
  if (typeof value !== 'string') return fallback

  const raw = value.trim()
  if (!raw || raw.length > 2048) return fallback
  if (/[\u0000-\u001f\u007f]/.test(raw)) return fallback
  if (raw.includes('\\') || /%5c/i.test(raw)) return fallback
  if (raw.startsWith('//')) return fallback

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)

  let candidate: URL
  try {
    if (hasScheme) {
      const parsed = new URL(raw)
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return fallback
      if (parsed.origin !== currentOrigin) return fallback
      if (parsed.username || parsed.password) return fallback
      candidate = parsed
    } else {
      const relative = raw.startsWith('/') ? raw : `/${raw}`
      candidate = new URL(relative, currentOrigin)
      if (candidate.origin !== currentOrigin) return fallback
      if (candidate.username || candidate.password) return fallback
    }
  } catch {
    return fallback
  }

  if (!candidate.pathname.startsWith('/')) return fallback
  if (candidate.pathname.startsWith('//')) return fallback
  if (!isWithinBasePath(candidate.pathname)) return fallback

  const result = `${candidate.pathname}${candidate.search}${candidate.hash}`
  return result.startsWith('//') ? fallback : result
}

export function currentReturnTo(): string {
  if (typeof window === 'undefined') return FALLBACK
  return sanitizeReturnTo(
    `${window.location.pathname}${window.location.search}${window.location.hash}`,
  )
}
