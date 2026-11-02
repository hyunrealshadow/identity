import type { Locale } from '#/lib/i18n'

export type GraphQLFailureKind =
  | 'unauthorized'
  | 'network'
  | 'http'
  | 'invalid_response'
  | 'graphql'

export interface GraphQLFieldError {
  path: string
  message?: string
  code?: string | number
}

export interface GraphQLStepUp {
  /** Local coordination only; never accepted as server policy. */
  recoveryManaged?: boolean
  acrValues?: string
  maxAge?: number
  requiredScopes?: string[]
  prompt?: 'login'
  source: 'graphql' | 'www-authenticate' | 'both' | 'preflight'
  requestId?: string
  traceId?: string
}

export interface GraphQLIssue {
  message: string
  path?: ReadonlyArray<string | number>
  kind?: string
  code?: string | number
  fields: GraphQLFieldError[]
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  extensions?: Record<string, unknown>
}

export interface GraphQLFailure {
  kind: GraphQLFailureKind
  code: string
  status?: number
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
}

export interface GraphQLResult<TData> {
  data: TData | null
  errors: GraphQLIssue[]
  requestId?: string
  traceId?: string
  failure?: GraphQLFailure
  partial: boolean
  unauthorized: boolean
  forbidden: boolean
  stepUp?: GraphQLStepUp
}

export interface ExecuteGraphQLOptions<TVariables> {
  graphqlUrl: string
  accessToken: string
  locale: Locale
  variables: TVariables
  operationName?: string
  fetchImpl?: typeof fetch
  signal?: AbortSignal
  /** A valid 32-character lowercase W3C trace ID from an active local trace. */
  activeTraceId?: string
}

export interface DocumentSource<TData, TVariables> {
  readonly __apiType?: (variables: TVariables) => TData
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/
const TRACE_ID_PATTERN = /^[0-9a-f]{32}$/

function validRequestId(value: unknown): string | undefined {
  return typeof value === 'string' && REQUEST_ID_PATTERN.test(value) ? value : undefined
}

function validTraceId(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '0'.repeat(32) && TRACE_ID_PATTERN.test(value) ? value : undefined
}

export function graphqlDocumentText<TData = unknown, TVariables = unknown>(
  document: string | DocumentSource<TData, TVariables>,
): string {
  if (typeof document === 'string') return document

  if (document !== null && typeof document === 'object') {
    const candidate = document as { loc?: { source?: { body?: unknown } } }
    const body = candidate.loc?.source?.body
    if (typeof body === 'string') return body

    try {
      const source = String(document)
      if (source && source !== '[object Object]') return source
    } catch {
      // Fall through to the shared error below.
    }
  }

  throw new Error('GraphQL document must be generated with documentMode "string"')
}

function pathValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) return value
  if (Array.isArray(value)) {
    const parts = value.filter(
      (part): part is string | number => typeof part === 'string' || typeof part === 'number',
    )
    const field = [...parts].reverse().find((part) => typeof part === 'string' && part !== 'input')
    return field === undefined ? undefined : String(field)
  }
  return undefined
}

function fieldErrors(value: unknown): GraphQLFieldError[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => {
      if (typeof entry === 'string') return []
      if (typeof entry !== 'object' || entry === null) return []
      const record = entry as Record<string, unknown>
      const path = pathValue(record.path) ?? pathValue(record.field) ?? pathValue(record.name)
      if (!path) return []
      const error: GraphQLFieldError = { path }
      if (typeof record.message === 'string') error.message = record.message
      if (typeof record.code === 'string' || typeof record.code === 'number') {
        error.code = record.code
      }
      return [error]
    })
  }

  if (typeof value === 'object' && value !== null) {
    return Object.entries(value as Record<string, unknown>).flatMap(([path, detail]) => {
      if (typeof detail === 'string') return [{ path, message: detail }]
      if (typeof detail !== 'object' || detail === null) return [{ path }]
      const record = detail as Record<string, unknown>
      const error: GraphQLFieldError = { path }
      if (typeof record.message === 'string') error.message = record.message
      if (typeof record.code === 'string' || typeof record.code === 'number') {
        error.code = record.code
      }
      return [error]
    })
  }

  return []
}

function exts(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

function stableCode(value: unknown): string | number | undefined {
  return typeof value === 'string' || typeof value === 'number' ? value : undefined
}

function stepUpCode(value: unknown): boolean {
  const code = typeof value === 'string' ? value.toLowerCase() : ''
  return (
    code === 'insufficient_user_authentication' ||
    code === 'insufficient_authentication' ||
    code === 'authentication_required' ||
    code === 'step_up_required'
  )
}

function acrValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value.trim()
  if (Array.isArray(value)) {
    const values = value.filter((entry): entry is string => typeof entry === 'string' && !!entry)
    return values.length > 0 ? values.join(' ') : undefined
  }
  return undefined
}

function maxAgeValue(value: unknown): number | undefined {
  const number = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN
  return Number.isInteger(number) && number >= 0 ? number : undefined
}

function scopeValues(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const values = value.filter((entry): entry is string => typeof entry === 'string' && !!entry)
    return values.length > 0 ? values : undefined
  }
  if (typeof value === 'string' && value.trim()) return value.trim().split(/\s+/)
  return undefined
}

function parseWwwAuthenticate(header: string | null): GraphQLStepUp | undefined {
  if (!header) return undefined

  const parameters = new Map<string, string>()
  const pattern = /([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g
  for (const match of header.matchAll(pattern)) {
    parameters.set(match[1].toLowerCase(), (match[2] ?? match[3] ?? '').replace(/\\(.)/g, '$1'))
  }

  if (!stepUpCode(parameters.get('error'))) return undefined

  const result: GraphQLStepUp = { source: 'www-authenticate' }
  const acr = acrValue(parameters.get('acr_values'))
  const maxAge = maxAgeValue(parameters.get('max_age'))
  const scopes = scopeValues(parameters.get('required_scopes') ?? parameters.get('scope'))
  if (acr) result.acrValues = acr
  if (maxAge !== undefined) result.maxAge = maxAge
  if (scopes) result.requiredScopes = scopes
  return result
}

function mergeStepUp(
  graphql: GraphQLStepUp | undefined,
  header: GraphQLStepUp | undefined,
): GraphQLStepUp | undefined {
  if (!graphql) return header
  if (!header) return graphql
  const merged: GraphQLStepUp = { source: 'both' }
  const acrValues = graphql.acrValues ?? header.acrValues
  const maxAge = graphql.maxAge ?? header.maxAge
  const requiredScopes = graphql.requiredScopes ?? header.requiredScopes
  if (acrValues) merged.acrValues = acrValues
  if (maxAge !== undefined) merged.maxAge = maxAge
  if (requiredScopes) merged.requiredScopes = requiredScopes
  if (graphql.requestId ?? header.requestId) merged.requestId = graphql.requestId ?? header.requestId
  if (graphql.traceId ?? header.traceId) merged.traceId = graphql.traceId ?? header.traceId
  return merged
}

function issueStepUp(
  extensions: Record<string, unknown>,
  requestIdValue: string | undefined,
  traceIdValue: string | undefined,
): GraphQLStepUp | undefined {
  if (!stepUpCode(extensions.code) && !stepUpCode(extensions.kind)) return undefined
  const stepUp: GraphQLStepUp = { source: 'graphql' }
  const acr = acrValue(extensions.acr_values ?? extensions.acrValues)
  const maxAge = maxAgeValue(extensions.max_age ?? extensions.maxAge)
  const scopes = scopeValues(extensions.required_scopes ?? extensions.requiredScopes)
  if (acr) stepUp.acrValues = acr
  if (maxAge !== undefined) stepUp.maxAge = maxAge
  if (scopes) stepUp.requiredScopes = scopes
  if (requestIdValue) stepUp.requestId = requestIdValue
  if (traceIdValue) stepUp.traceId = traceIdValue
  return stepUp
}

function isForbiddenCode(kind: string | undefined, code: string | number | undefined): boolean {
  const value = `${kind ?? ''} ${String(code ?? '')}`.toLowerCase()
  return (
    value.includes('forbidden') ||
    value.includes('insufficient_scope') ||
    value.includes('permission_denied') ||
    value.includes('access_denied')
  )
}

export async function executeGraphQL<TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  options: ExecuteGraphQLOptions<TVariables>,
): Promise<GraphQLResult<TData>> {
  if (!options.accessToken) {
    return {
      data: null,
      errors: [],
      failure: { kind: 'unauthorized', code: 'missing_access_token' },
      partial: false,
      unauthorized: true,
      forbidden: false,
    }
  }

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Accept-Language': options.locale,
    Authorization: `Bearer ${options.accessToken}`,
    'Content-Type': 'application/json',
  }

  let query: string
  try {
    query = graphqlDocumentText(document)
  } catch {
    return {
      data: null,
      errors: [],
      failure: { kind: 'invalid_response', code: 'invalid_document' },
      partial: false,
      unauthorized: false,
      forbidden: false,
    }
  }

  let response: Response
  try {
    response = await (options.fetchImpl ?? globalThis.fetch)(options.graphqlUrl, {
      method: 'POST',
      credentials: 'omit',
      headers,
      body: JSON.stringify({
        query,
        variables: options.variables,
        operationName: options.operationName,
      }),
      signal: options.signal,
    })
  } catch {
    return {
      data: null,
      errors: [],
      failure: { kind: 'network', code: 'network_error' },
      partial: false,
      unauthorized: false,
      forbidden: false,
    }
  }

  const headerRequestId = validRequestId(response.headers.get('X-Request-ID'))
  const headerTraceId = validTraceId(response.headers.get('X-Trace-ID'))
  const headerStepUp = parseWwwAuthenticate(response.headers.get('WWW-Authenticate'))

  let rawBody: string
  try {
    rawBody = await response.text()
  } catch {
    return {
      data: null,
      errors: [],
      requestId: headerRequestId,
      traceId: headerTraceId,
      failure: {
        kind: 'invalid_response',
        code: 'unreadable_response',
        status: response.status,
        requestId: headerRequestId,
        traceId: headerTraceId,
        stepUp: headerStepUp,
      },
      partial: false,
      unauthorized: response.status === 401 && !headerStepUp,
      forbidden: false,
      stepUp: headerStepUp,
    }
  }

  let payload: unknown
  try {
    payload = rawBody ? JSON.parse(rawBody) : null
  } catch {
    return {
      data: null,
      errors: [],
      requestId: headerRequestId,
      traceId: headerTraceId,
      failure: {
        kind: response.status === 401 ? 'unauthorized' : 'invalid_response',
        code: response.status === 401 ? 'unauthenticated' : 'invalid_json',
        status: response.status,
        requestId: headerRequestId,
        traceId: headerTraceId,
        stepUp: headerStepUp,
      },
      partial: false,
      unauthorized: response.status === 401 && !headerStepUp,
      forbidden: false,
      stepUp: headerStepUp,
    }
  }

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return {
      data: null,
      errors: [],
      requestId: headerRequestId,
      traceId: headerTraceId,
      failure: {
        kind: 'invalid_response',
        code: 'invalid_response_shape',
        status: response.status,
        requestId: headerRequestId,
        traceId: headerTraceId,
        stepUp: headerStepUp,
      },
      partial: false,
      unauthorized: response.status === 401 && !headerStepUp,
      forbidden: false,
      stepUp: headerStepUp,
    }
  }

  const body = payload as {
    data?: TData | null
    errors?: unknown
    extensions?: unknown
  }
  const responseExtensions = exts(body.extensions)
  const responseRequestId =
    validRequestId(responseExtensions.requestId) ?? headerRequestId
  const responseTraceId =
    validTraceId(responseExtensions.traceId) ?? headerTraceId

  const rawErrors = Array.isArray(body.errors) ? body.errors : []
  const issues: GraphQLIssue[] = rawErrors.map((entry) => {
    const record = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {}
    const extensions = exts(record.extensions)
    const errorRequestId = validRequestId(extensions.requestId) ?? responseRequestId
    const errorTraceId = validTraceId(extensions.traceId) ?? responseTraceId
    const issue: GraphQLIssue = {
      message: typeof record.message === 'string' ? record.message : '',
      fields: fieldErrors(extensions.fields),
    }
    if (Array.isArray(record.path)) issue.path = record.path as ReadonlyArray<string | number>
    if (typeof extensions.kind === 'string') issue.kind = extensions.kind
    const code = stableCode(extensions.code)
    if (code !== undefined) issue.code = code
    const errorStepUp = issueStepUp(extensions, errorRequestId, errorTraceId)
    if (errorRequestId) issue.requestId = errorRequestId
    if (errorTraceId) issue.traceId = errorTraceId
    if (errorStepUp) issue.stepUp = errorStepUp
    if (Object.keys(extensions).length > 0) issue.extensions = extensions
    return issue
  })

  const graphqlStepUp = issues.find((issue) => issue.stepUp)?.stepUp
  const stepUp = mergeStepUp(graphqlStepUp, headerStepUp)
  const unauthorized = !stepUp && (
    response.status === 401 ||
    issues.some((issue) => {
      const value = `${issue.kind ?? ''} ${String(issue.code ?? '')}`.toLowerCase()
      return value.includes('unauthenticated') || value.includes('unauthorized')
    }))
  const forbidden =
    response.status === 403 ||
    issues.some((issue) => isForbiddenCode(issue.kind, issue.code))
  const data = body.data ?? null
  const partial = data !== null && issues.length > 0

  if (unauthorized) {
    return {
      data,
      errors: issues,
      requestId: responseRequestId,
      traceId: responseTraceId,
      failure: {
        kind: 'unauthorized',
        code: String(issues[0]?.code ?? 'unauthenticated'),
        status: response.status,
        requestId: responseRequestId,
        traceId: responseTraceId,
        stepUp,
      },
      partial,
      unauthorized: true,
      forbidden,
      stepUp,
    }
  }

  if (issues.length > 0) {
    const first = issues[0]
    return {
      data,
      errors: issues,
      requestId: responseRequestId,
      traceId: responseTraceId,
      failure: {
        kind: 'graphql',
        code: String(first.code ?? first.kind ?? 'graphql_error'),
        status: response.status,
        requestId: responseRequestId,
        traceId: responseTraceId,
        stepUp,
      },
      partial,
      unauthorized: false,
      forbidden,
      stepUp,
    }
  }

  if (!response.ok) {
    return {
      data,
      errors: issues,
      requestId: responseRequestId,
      traceId: responseTraceId,
      failure: {
        kind: 'http',
        code: `http_${response.status}`,
        status: response.status,
        requestId: responseRequestId,
        traceId: responseTraceId,
        stepUp,
      },
      partial,
      unauthorized: false,
      forbidden: false,
      stepUp,
    }
  }

  if (body.data === undefined) {
    return {
      data: null,
      errors: issues,
      requestId: responseRequestId,
      traceId: responseTraceId,
      failure: {
        kind: 'invalid_response',
        code: 'missing_data',
        status: response.status,
        requestId: responseRequestId,
        traceId: responseTraceId,
      },
      partial: false,
      unauthorized: false,
      forbidden: false,
      stepUp,
    }
  }

  return {
    data,
    errors: issues,
    requestId: responseRequestId,
    traceId: responseTraceId,
    partial,
    unauthorized: false,
    forbidden,
    stepUp,
  }
}

export function fieldErrorMap(issues: ReadonlyArray<GraphQLIssue>): Record<string, string> {
  const result: Record<string, string> = {}
  for (const issue of issues) {
    for (const field of issue.fields) {
      if (!result[field.path]) {
        result[field.path] = field.message ?? field.code?.toString() ?? ''
      }
    }
  }
  return result
}
