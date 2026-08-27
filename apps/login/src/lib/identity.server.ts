import {
  getRequestHeader,
  setResponseHeader,
} from '@tanstack/react-start/server'
import { readFileSync } from 'node:fs'

import type {
  BusinessErrorResponse,
  FieldErrorResponse,
} from './identity-types'
import type { Locale } from './i18n'
import { translate } from './i18n'
import { forwardRequestContext } from './request-context.server'

const DEFAULT_IDENTITY_URL = 'https://localhost:5150'
const SESSION_COOKIE_NAME = 'identity.sessions'
const SESSION_HEADER_NAME = 'x-sessions'
const CSRF_HEADER_NAME = 'x-csrf-token'
const SESSION_MAX_AGE = 7 * 24 * 60 * 60
const TERMINAL_LOGIN_ERROR_CODES = new Set([11004, 11005])

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

export function isTerminalLoginError(error: unknown) {
  return (
    error instanceof IdentityApiError &&
    error.code !== undefined &&
    TERMINAL_LOGIN_ERROR_CODES.has(error.code)
  )
}

function apiBaseUrl() {
  const url = new URL(process.env.IDENTITY_API_URL ?? DEFAULT_IDENTITY_URL)
  if (url.protocol !== 'https:') {
    throw new Error('IDENTITY_API_URL must use HTTPS')
  }
  return url
}

function internalApiBaseUrl() {
  const url = new URL(
    process.env.IDENTITY_INTERNAL_API_URL ?? 'https://localhost:5151',
  )
  if (url.protocol !== 'https:') {
    throw new Error('IDENTITY_INTERNAL_API_URL must use HTTPS')
  }
  return url
}

function workloadToken() {
  const file = process.env.IDENTITY_WORKLOAD_TOKEN_FILE
  const inline = process.env.IDENTITY_WORKLOAD_TOKEN
  if (!file && !inline) {
    throw new Error(
      'IDENTITY_WORKLOAD_TOKEN_FILE or IDENTITY_WORKLOAD_TOKEN must be configured to call the Identity internal API',
    )
  }
  if (file) {
    return readFileSync(file, 'utf8').trim()
  }
  return (inline ?? '').trim()
}

export async function internalApiToken() {
  const token = workloadToken()
  if (token.length < 32) {
    throw new Error(
      'The Identity workload token must contain at least 32 characters',
    )
  }
  return token
}

function requestHeaders(sessions = requestSessionIds()) {
  const headers = forwardRequestContext(
    new Headers({ accept: 'application/json' }),
  )

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

function sameSessionIds(current: Array<string>, next: Array<string>) {
  return current.length === next.length &&
    current.every((session, index) => session === next[index])
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
  const currentSessions = requestSessionIds()
  const headers = requestHeaders(currentSessions)
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
  if (sessions && !sameSessionIds(currentSessions, sessions)) {
    storeSessionIds(sessions)
  }

  return payload as T
}

export async function identityInternalJson<T>(
  path: string,
  init?: {
    method?: 'GET' | 'POST'
    body?: Record<string, unknown>
  },
) {
  const headers = new Headers({ accept: 'application/json' })
  headers.set('authorization', `Bearer ${await internalApiToken()}`)
  if (init?.body) headers.set('content-type', 'application/json')
  const response = await fetch(new URL(path, internalApiBaseUrl()), {
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
      `Identity internal API request failed (${response.status})`,
      response.status,
    )
  }
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
