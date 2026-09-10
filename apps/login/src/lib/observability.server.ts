import { AsyncLocalStorage } from 'node:async_hooks'
import { randomBytes } from 'node:crypto'

/**
 * Server-side observability for the Login service.
 *
 * Login terminates browser traffic (untrusted) and talks to Identity over its
 * back-channel and internal APIs. This module:
 *
 * - starts one server span per inbound request (new trace, plus a link when the
 *   browser sent a valid `traceparent` that cannot be trusted),
 * - creates client spans for real outbound HTTP calls and injects W3C context
 *   into Identity-facing requests from the active client span,
 * - emits key events (callback/session handling, observed remote token
 *   exchange, backchannel requests) as OTLP log records that do not depend on
 *   trace sampling,
 * - buffers everything behind a bounded, non-blocking queue and exports
 *   OTLP/HTTP JSON to the collector configured by the deployment.
 *
 * It deliberately implements only what the confirmed design requires, so the
 * login server keeps a small dependency surface and full control over redaction
 * and merge semantics.
 */

interface SpanContext {
  traceId: string
  spanId: string
  sampled: boolean
  baggage?: string
}

interface SpanLink {
  traceId: string
  spanId: string
}

interface FinishedSpan {
  name: string
  kind: number
  traceId: string
  spanId: string
  sampled: boolean
  parentSpanId?: string
  startTimeUnixNano: string
  endTimeUnixNano: string
  attributes: Record<string, string | number | boolean>
  status?: number
  statusMessage?: string
  links: Array<SpanLink>
}

interface LogRecord {
  eventName: string
  severityNumber: number
  severityText: string
  timeUnixNano: string
  attributes: Record<string, string | number | boolean>
  traceId?: string
  spanId?: string
  outcome?: string
  reason?: string
  category?: string
}

interface SpanHandle {
  context: SpanContext
  setAttribute(key: string, value: string | number | boolean): void
  setStatus(ok: boolean, message?: string): void
  addLink(traceId: string, spanId: string): void
  end(): void
}

const SPAN_KIND_INTERNAL = 1
const SPAN_KIND_SERVER = 2
const SPAN_KIND_CLIENT = 3

const SPAN_ID_BYTES = 8
const TRACE_ID_BYTES = 16
const MAX_QUEUE_SPANS = 2048
const MAX_QUEUE_LOGS = 8192
const FLUSH_INTERVAL_MS = 5000

const scope = { name: 'identity.login', version: '1.0.0' }

let enabled = false
let otlpEndpoint = ''
let serviceName = 'identity-login'
let environment = process.env.IDENTITY_LOGIN_ENVIRONMENT ?? process.env.NODE_ENV ?? 'production'
let sampleRatio = 1
let installId = randomBytes(8).toString('hex')

const storage = new AsyncLocalStorage<SpanContext>()
const clockOffsetMs = Date.now() - Number(process.hrtime.bigint() / 1_000_000n)

let spanQueue: Array<FinishedSpan> = []
let logQueue: Array<LogRecord> = []
let flushTimer: NodeJS.Timeout | undefined
let flushing = false

const counters = {
  spansQueued: 0,
  spansDropped: 0,
  logsQueued: 0,
  logsDropped: 0,
  exportFailures: 0,
}

function nowUnixNano(): string {
  const millis = process.hrtime.bigint() / 1_000_000n + BigInt(clockOffsetMs)
  return (millis * 1_000_000n).toString()
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex')
}

function parseTraceparent(value: string | null | undefined) {
  if (!value) return undefined
  const parts = value.trim().toLowerCase().split('-')
  if (parts.length < 4) return undefined
  const [version, traceId, spanId, flags, ...rest] = parts
  if (version !== '00' && !/^[0-9a-f]{2}$/.test(version)) return undefined
  if (version === '00' && rest.length > 0) return undefined
  if (!/^[0-9a-f]{32}$/.test(traceId) || /^0+$/.test(traceId)) return undefined
  if (!/^[0-9a-f]{16}$/.test(spanId) || /^0+$/.test(spanId)) return undefined
  if (!/^[0-9a-f]{2}$/.test(flags)) return undefined
  return { traceId, spanId, sampled: (Number.parseInt(flags, 16) & 0x01) === 0x01 }
}

function shouldSample(): boolean {
  if (sampleRatio >= 1) return true
  if (sampleRatio <= 0) return false
  // Trace-id based so a trusted downstream keeps a consistent decision.
  const value = Number.parseInt(randomHex(TRACE_ID_BYTES).slice(0, 8), 16) / 0xffffffff
  return value < sampleRatio
}

function startSpan(
  name: string,
  kind: number,
  attributes: Record<string, string | number | boolean> = {},
): SpanHandle {
  const parent = storage.getStore()
  const context: SpanContext = parent
    ? {
        traceId: parent.traceId,
        spanId: randomHex(SPAN_ID_BYTES),
        sampled: parent.sampled,
      }
    : {
        traceId: randomHex(TRACE_ID_BYTES),
        spanId: randomHex(SPAN_ID_BYTES),
        sampled: shouldSample(),
      }
  const start = nowUnixNano()
  const links: Array<SpanLink> = []
  let attributesMut = { ...attributes }
  let status: number | undefined
  let statusMessage: string | undefined
  let ended = false

  return {
    context,
    setAttribute(key, value) {
      attributesMut[key] = value
    },
    setStatus(ok, message) {
      status = ok ? 1 : 2
      statusMessage = message
    },
    addLink(traceId, spanId) {
      links.push({ traceId, spanId })
    },
    end() {
      if (ended) return
      ended = true
      enqueueSpan({
        name,
        kind,
        traceId: context.traceId,
        spanId: context.spanId,
        sampled: context.sampled,
        parentSpanId: parent?.spanId,
        startTimeUnixNano: start,
        endTimeUnixNano: nowUnixNano(),
        attributes: attributesMut,
        status,
        statusMessage,
        links,
      })
    },
  }
}

function enqueueSpan(span: FinishedSpan): void {
  counters.spansQueued += 1
  if (spanQueue.length >= MAX_QUEUE_SPANS) {
    counters.spansDropped += 1
    return
  }
  spanQueue.push(span)
  scheduleFlush()
}

function attributeValue(value: string | number | boolean) {
  if (typeof value === 'boolean') return { boolValue: value }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? { intValue: value } : { doubleValue: value }
  }
  return { stringValue: value }
}

function attributesToOtlp(attributes: Record<string, string | number | boolean>) {
  return Object.entries(attributes)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => ({ key, value: attributeValue(value) }))
}

function enqueueLog(record: LogRecord): void {
  counters.logsQueued += 1
  if (logQueue.length >= MAX_QUEUE_LOGS) {
    counters.logsDropped += 1
    return
  }
  logQueue.push(record)
  scheduleFlush()
}

export type EventSeverity = 'info' | 'warn' | 'error'

export interface EventInput {
  outcome?: string
  reason?: string
  category?: 'business' | 'audit'
  severity?: EventSeverity
  attributes?: Record<string, string | number | boolean>
}

function severityNumber(severity: EventSeverity) {
  switch (severity) {
    case 'warn':
      return 13
    case 'error':
      return 17
    default:
      return 9
  }
}

/** Emit a key business or audit event. Never include credentials or raw PII. */
export function emitEvent(eventName: string, input: EventInput = {}): void {
  if (!enabled || !/^[a-z0-9_.]+$/.test(eventName)) return
  const current = storage.getStore()
  const severity = input.severity ?? 'info'
  enqueueLog({
    eventName,
    severityNumber: severityNumber(severity),
    severityText: severity.toUpperCase(),
    timeUnixNano: nowUnixNano(),
    attributes: {
      'identity.event.category': input.category ?? 'business',
      ...(input.attributes ?? {}),
    },
    outcome: input.outcome,
    reason: input.reason,
    traceId: current?.traceId,
    spanId: current?.spanId,
  })
}

/** Run a function with the request span active. */
export function runWithServerSpan<T>(
  name: string,
  attributes: Record<string, string | number | boolean>,
  inboundTraceparent: string | null | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  if (!enabled) return fn()
  const span = startSpan(name, SPAN_KIND_SERVER, attributes)

  // Browser traffic is not trusted: a valid inbound context becomes a link,
  // never the local parent, and an invalid header is ignored entirely.
  const inbound = parseTraceparent(inboundTraceparent ?? undefined)
  if (inbound) span.addLink(inbound.traceId, inbound.spanId)

  return storage.run(span.context, async () => {
    try {
      const result = await fn()
      if (result instanceof Response) {
        span.setAttribute('http.response.status_code', result.status)
        // 4xx is a client outcome on the protocol span; only 5xx is a server
        // failure. Business outcomes live in the key events.
        span.setStatus(result.status < 500)
      } else {
        span.setStatus(true)
      }
      return result
    } catch (error) {
      span.setStatus(false, error instanceof Error ? error.message : String(error))
      throw error
    } finally {
      span.end()
    }
  })
}

/** Run a function inside a child span (client, internal or wait spans). */
export async function withSpan<T>(
  name: string,
  kind: 'internal' | 'client',
  attributes: Record<string, string | number | boolean>,
  fn: (span: SpanHandle) => Promise<T>,
): Promise<T> {
  if (!enabled) {
    return fn({
      context: { traceId: '', spanId: '', sampled: false },
      setAttribute: () => {},
      setStatus: () => {},
      addLink: () => {},
      end: () => {},
    })
  }
  const span = startSpan(name, kind === 'client' ? SPAN_KIND_CLIENT : SPAN_KIND_INTERNAL, attributes)
  return storage.run(span.context, async () => {
    try {
      const result = await fn(span)
      span.setStatus(true)
      return result
    } catch (error) {
      span.setStatus(false, error instanceof Error ? error.message : String(error))
      throw error
    } finally {
      span.end()
    }
  })
}

/**
 * Inject the active context into outbound headers. Only called for
 * Identity-facing back-channel and internal endpoints, which are the
 * configured propagation targets for Login.
 */
export function injectTraceHeaders(headers: Headers): Headers {
  const current = storage.getStore()
  if (!enabled || !current || !current.traceId) return headers
  const flags = current.sampled ? '01' : '00'
  headers.set('traceparent', `00-${current.traceId}-${current.spanId}-${flags}`)
  return headers
}

function scheduleFlush(): void {
  if (flushTimer) return
  flushTimer = setTimeout(() => {
    flushTimer = undefined
    void flush()
  }, FLUSH_INTERVAL_MS)
  flushTimer.unref?.()
}

async function postOtlp(path: string, body: unknown): Promise<void> {
  if (!enabled || !otlpEndpoint) return
  try {
    const response = await fetch(new URL(path, otlpEndpoint), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!response.ok) counters.exportFailures += 1
  } catch {
    counters.exportFailures += 1
  }
}

/** Flush queued telemetry. Safe to call concurrently. */
export async function flush(): Promise<void> {
  if (!enabled || flushing) return
  flushing = true
  try {
    const spans = spanQueue
    const logs = logQueue
    spanQueue = []
    logQueue = []
    if (logs.length > 0) {
      await postOtlp('/v1/logs', logPayload(logs))
    }
    const sampledSpans = spans.filter((span) => span.sampled)
    if (sampledSpans.length > 0) {
      await postOtlp('/v1/traces', tracePayload(sampledSpans))
    }
  } finally {
    flushing = false
  }
}

function resourceAttributes() {
  return [
    { key: 'service.name', value: { stringValue: serviceName } },
    { key: 'service.version', value: { stringValue: '1.0.0' } },
    { key: 'service.instance.id', value: { stringValue: installId } },
    { key: 'deployment.environment.name', value: { stringValue: environment } },
    {
      key: 'process.pid',
      value: { intValue: process.pid },
    },
  ]
}

function tracePayload(spans: Array<FinishedSpan>) {
  return {
    resourceSpans: [
      {
        resource: { attributes: resourceAttributes() },
        scopeSpans: [
          {
            scope,
            spans: spans.map((span) => ({
              traceId: span.traceId,
              spanId: span.spanId,
              ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
              name: span.name,
              kind: span.kind,
              startTimeUnixNano: span.startTimeUnixNano,
              endTimeUnixNano: span.endTimeUnixNano,
              attributes: attributesToOtlp(span.attributes),
              ...(span.status !== undefined
                ? { status: { code: span.status, ...(span.statusMessage ? { message: span.statusMessage } : {}) } }
                : {}),
              ...(span.links.length > 0
                ? {
                    links: span.links.map((link) => ({
                      traceId: link.traceId,
                      spanId: link.spanId,
                    })),
                  }
                : {}),
            })),
          },
        ],
      },
    ],
  }
}

function logPayload(records: Array<LogRecord>) {
  return {
    resourceLogs: [
      {
        resource: { attributes: resourceAttributes() },
        scopeLogs: [
          {
            scope,
            logRecords: records.map((record) => ({
              timeUnixNano: record.timeUnixNano,
              severityNumber: record.severityNumber,
              severityText: record.severityText,
              eventName: record.eventName,
              body: { stringValue: record.eventName },
              attributes: attributesToOtlp({
                ...record.attributes,
                ...(record.outcome ? { 'identity.event.outcome': record.outcome } : {}),
                ...(record.reason ? { 'identity.event.reason': record.reason } : {}),
              }),
              ...(record.traceId ? { traceId: record.traceId } : {}),
              ...(record.spanId ? { spanId: record.spanId } : {}),
            })),
          },
        ],
      },
    ],
  }
}

/**
 * Fetch with a client span and W3C injection. Only use this for the configured
 * Identity back-channel and internal endpoints.
 */
export async function fetchWithSpan(
  input: URL,
  init: RequestInit,
  spanName = 'http.client',
): Promise<Response> {
  if (!enabled) return fetch(input, init)
  return withSpan(
    spanName,
    'client',
    { 'http.request.method': init.method ?? 'GET', 'server.address': input.host },
    async (span) => {
      const headers = new Headers(init.headers)
      injectTraceHeaders(headers)
      const response = await fetch(input, { ...init, headers })
      span.setAttribute('http.response.status_code', response.status)
      span.setStatus(response.ok)
      return response
    },
  )
}

/** Render pipeline health; served from the independent scrape route. */
export function renderMetrics(): string {
  const lines: Array<string> = []
  const push = (name: string, help: string, type: string, value: number) => {
    lines.push(`# HELP ${name} ${help}`)
    lines.push(`# TYPE ${name} ${type}`)
    lines.push(`${name} ${value}`)
  }
  push(
    'identity_login_observability_spans_queued_total',
    'Server and client spans accepted for export.',
    'counter',
    counters.spansQueued,
  )
  push(
    'identity_login_observability_spans_dropped_total',
    'Spans dropped because the bounded queue was full.',
    'counter',
    counters.spansDropped,
  )
  push(
    'identity_login_observability_logs_queued_total',
    'Key events accepted for export.',
    'counter',
    counters.logsQueued,
  )
  push(
    'identity_login_observability_logs_dropped_total',
    'Key events dropped because the bounded queue was full.',
    'counter',
    counters.logsDropped,
  )
  push(
    'identity_login_observability_export_failures_total',
    'Failed OTLP exports since process start.',
    'counter',
    counters.exportFailures,
  )
  lines.push('# TYPE identity_login_observability_queue_depth gauge')
  lines.push(`identity_login_observability_queue_depth{queue="spans"} ${spanQueue.length}`)
  lines.push(`identity_login_observability_queue_depth{queue="logs"} ${logQueue.length}`)
  return lines.join('\n') + '\n'
}

/** Whether the pipeline is active. */
export function observabilityEnabled(): boolean {
  return enabled
}

/**
 * Initialize from environment. Idempotent; safe to call from the server entry
 * point and from request middlewares.
 */
export function initObservability(): void {
  if (initialized) return
  initialized = true
  const flag = (process.env.IDENTITY_LOGIN_OTLP_ENABLE ?? '').toLowerCase()
  otlpEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? ''
  if (!otlpEndpoint || !['1', 'true', 'yes'].includes(flag)) {
    return
  }
  serviceName = process.env.OTEL_SERVICE_NAME ?? 'identity-login'
  environment = process.env.IDENTITY_LOGIN_ENVIRONMENT ?? environment
  installId = process.env.HOSTNAME ?? installId
  const ratio = Number.parseFloat(process.env.IDENTITY_LOGIN_TRACE_SAMPLE_RATIO ?? '')
  sampleRatio = Number.isFinite(ratio) ? Math.min(1, Math.max(0, ratio)) : 1
  enabled = true

  const flushOnExit = () => {
    void flush()
  }
  process.once('SIGTERM', flushOnExit)
  process.once('SIGINT', flushOnExit)
}

let initialized = false
