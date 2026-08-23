import { getRequestHeader } from '@tanstack/react-start/server'

const FORWARDED_CONTEXT_HEADERS = [
  'accept-language',
  'user-agent',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-real-ip',
  'x-request-id',
] as const

/**
 * Copy browser/request metadata needed for locale, audit, device, and client-IP
 * attribution. Authentication and routing headers are deliberately excluded.
 */
export function forwardRequestContext(headers: Headers) {
  for (const name of FORWARDED_CONTEXT_HEADERS) {
    const value = getRequestHeader(name)
    if (value) headers.set(name, value)
  }
  return headers
}
