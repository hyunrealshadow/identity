import {
  deleteCookie,
  getCookie,
} from '@tanstack/react-start/server'

import type { EnhancedNavigationResponse } from './identity-types'

const ENHANCED_FORM_HEADER = 'x-enhanced-form'
const FLASH_COOKIE_PREFIX = 'identity.form-flash.'

interface FormFlash {
  message: string
  values: Record<string, string | undefined>
  fields?: Record<string, string>
  /** Set when the message belongs to a form field (FieldError) instead of
      the page-level alert. */
  field?: string
}

function flashCookieName(pathname: string) {
  return `${FLASH_COOKIE_PREFIX}${pathname.replaceAll(/[^a-z0-9]/gi, '_')}`
}

function serializeFlash(flash: FormFlash) {
  return encodeURIComponent(JSON.stringify(flash))
}

function parseFlash(value: string | undefined): FormFlash | undefined {
  if (!value) return
  try {
    const parsed = JSON.parse(decodeURIComponent(value)) as unknown
    if (
      parsed &&
      typeof parsed === 'object' &&
      'message' in parsed &&
      typeof parsed.message === 'string' &&
      'values' in parsed &&
      parsed.values &&
      typeof parsed.values === 'object'
    ) {
      return parsed as FormFlash
    }
  } catch {
    // Ignore malformed or stale client cookies.
  }
}

export function consumeFormFlash(pathname: string) {
  const name = flashCookieName(pathname)
  const flash = parseFlash(getCookie(name))
  if (flash) deleteCookie(name, { path: pathname })
  return flash
}

export function navigationResponse(request: Request, destination: string) {
  if (request.headers.get(ENHANCED_FORM_HEADER) === '1') {
    return Response.json({ redirect: destination } satisfies EnhancedNavigationResponse)
  }

  return new Response(null, {
    status: 303,
    headers: { location: destination },
  })
}

export function formErrorResponse(
  request: Request,
  pathname: string,
  message: string,
  values: Record<string, string | undefined>,
  field?: string,
  destination = pathname,
) {
  const response = navigationResponse(request, new URL(destination, request.url).toString())
  response.headers.append(
    'set-cookie',
    `${flashCookieName(pathname)}=${serializeFlash({ message, values, field })}; Path=${pathname}; Max-Age=60; HttpOnly; Secure; SameSite=Lax`,
  )
  return response
}

export function formValidationErrorResponse(
  request: Request,
  pathname: string,
  message: string,
  values: Record<string, string | undefined>,
  fields: Record<string, string>,
  destination = pathname,
) {
  const response = navigationResponse(request, new URL(destination, request.url).toString())
  response.headers.append(
    'set-cookie',
    `${flashCookieName(pathname)}=${serializeFlash({ message, values, fields })}; Path=${pathname}; Max-Age=60; HttpOnly; Secure; SameSite=Lax`,
  )
  return response
}
