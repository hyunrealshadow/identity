import {
  getRequestHeader,
  setResponseHeader,
} from '@tanstack/react-start/server'

import type {
  BusinessErrorResponse,
  FieldErrorResponse,
} from './identity-types'
import type { Locale } from './i18n'
import { translate } from './i18n'

const DEFAULT_IDENTITY_URL = 'https://localhost:5150'
const SESSION_COOKIE_NAME = 'identity.sessions'
const SESSION_HEADER_NAME = 'x-sessions'
const CSRF_HEADER_NAME = 'x-csrf-token'
const SESSION_MAX_AGE = 7 * 24 * 60 * 60

export class IdentityApiError extends Error {
  readonly code?: number
  readonly fields: Array<FieldErrorResponse>
  readonly status: number

  constructor(
    message: string,
    status: number,
    code?: number,
    fields: Array<FieldErrorResponse> = [],
  ) {
    super(message)
    this.name = 'IdentityApiError'
    this.status = status
    this.code = code
    this.fields = fields
  }
}

function apiBaseUrl() {
  const url = new URL(process.env.IDENTITY_API_URL ?? DEFAULT_IDENTITY_URL)
  if (url.protocol !== 'https:') {
    throw new Error('IDENTITY_API_URL must use HTTPS')
  }
  return url
}

function requestHeaders() {
  const headers = new Headers({ accept: 'application/json' })
  const language = getRequestHeader('accept-language')
  const sessions = requestSessionIds()

  if (language) headers.set('accept-language', language)
  headers.set(SESSION_HEADER_NAME, JSON.stringify(sessions))

  return headers
}

function requestSessionIds() {
  const cookieHeader = getRequestHeader('cookie') ?? ''
  const encoded = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE_NAME}=`))
    ?.slice(SESSION_COOKIE_NAME.length + 1)

  if (!encoded) return []

  try {
    const value = JSON.parse(decodeURIComponent(encoded)) as unknown
    return Array.isArray(value) && value.every((item) => typeof item === 'string')
      ? value
      : []
  } catch {
    return []
  }
}

function storeSessionIds(sessions: Array<string>) {
  const value = encodeURIComponent(JSON.stringify(sessions))
  setResponseHeader(
    'set-cookie',
    `${SESSION_COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`,
  )
}

function responseSessionIds(value: unknown): Array<string> | undefined {
  if (!value || typeof value !== 'object' || !('sessions' in value)) return
  const sessions = value.sessions
  if (!Array.isArray(sessions) || !sessions.every((item) => typeof item === 'string')) return
  return sessions
}

function isBusinessError(value: unknown): value is BusinessErrorResponse {
  if (!value || typeof value !== 'object' || !('error' in value)) return false
  const error = value.error
  return (
    !!error &&
    typeof error === 'object' &&
    'message' in error &&
    typeof error.message === 'string'
  )
}

function responseFieldErrors(
  fields: BusinessErrorResponse['error']['fields'],
): Array<FieldErrorResponse> {
  if (!Array.isArray(fields)) return []
  return fields.filter(
    (field): field is FieldErrorResponse =>
      !!field &&
      typeof field === 'object' &&
      typeof field.field === 'string' &&
      typeof field.code === 'number' &&
      typeof field.message === 'string',
  )
}

export async function identityJson<T>(
  path: string,
  init?: {
    method?: 'GET' | 'POST'
    body?: Record<string, unknown>
    csrfToken?: string
  },
) {
  const headers = requestHeaders()
  if (init?.body) headers.set('content-type', 'application/json')
  if (init?.csrfToken) headers.set(CSRF_HEADER_NAME, init.csrfToken)

  const response = await fetch(new URL(path, apiBaseUrl()), {
    method: init?.method ?? 'GET',
    headers,
    body: init?.body ? JSON.stringify(init.body) : undefined,
    redirect: 'manual',
  })

  const payload = (await response.json().catch(() => null)) as unknown
  if (!response.ok) {
    if (isBusinessError(payload)) {
      throw new IdentityApiError(
        payload.error.message,
        response.status,
        payload.error.code,
        responseFieldErrors(payload.error.fields),
      )
    }
    throw new IdentityApiError(
      `Identity API request failed (${response.status})`,
      response.status,
    )
  }

  const sessions = responseSessionIds(payload)
  if (sessions) storeSessionIds(sessions)

  return payload as T
}

export async function identityResponse(path: string) {
  const response = await fetch(new URL(path, apiBaseUrl()), {
    headers: requestHeaders(),
    redirect: 'manual',
  })
  const headers = new Headers()
  const omitted = new Set([
    'connection',
    'content-encoding',
    'content-length',
    'transfer-encoding',
  ])

  response.headers.forEach((value, name) => {
    if (!omitted.has(name.toLowerCase())) headers.append(name, value)
  })
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

export function errorMessage(error: unknown, locale: Locale = 'en-US') {
  if (error instanceof IdentityApiError) return error.message
  if (error instanceof Error) return error.message
  return translate(locale, 'temporaryError')
}
