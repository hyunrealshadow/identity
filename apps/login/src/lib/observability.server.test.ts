import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * The login observability module is configured from environment variables at
 * initialization time, so every test loads a fresh module instance after
 * setting the environment it wants to exercise.
 */
async function loadModule() {
  return await import('./observability.server')
}

function stubFetch(posts: Array<{ url: string; body: Record<string, unknown> }>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body =
        typeof init?.body === 'string'
          ? (JSON.parse(init.body) as Record<string, unknown>)
          : {}
      posts.push({ url: String(input), body })
      return new Response('{}', { status: 200 })
    }),
  )
}

describe('observability.server', () => {
  beforeEach(() => {
    process.env.IDENTITY_LOGIN_OTLP_ENABLE = 'true'
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'https://collector.example:4318'
    process.env.IDENTITY_LOGIN_TRACE_SAMPLE_RATIO = '1'
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    delete process.env.IDENTITY_LOGIN_OTLP_ENABLE
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT
    delete process.env.IDENTITY_LOGIN_TRACE_SAMPLE_RATIO
  })

  it('starts a new trace and links an untrusted inbound traceparent', async () => {
    const posts: Array<{ url: string; body: Record<string, unknown> }> = []
    stubFetch(posts)
    const { initObservability, runWithServerSpan, flush } = await loadModule()
    initObservability()

    const inbound = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    await runWithServerSpan(
      'http.server',
      { 'http.request.method': 'GET', 'url.path': '/callback' },
      inbound,
      async () => undefined,
    )
    await flush()

    const traces = posts.find((post) => post.url.endsWith('/v1/traces'))
    expect(traces).toBeDefined()
    const spans = (
      traces?.body as {
        resourceSpans: Array<{ scopeSpans: Array<{ spans: unknown[] }> }>
      }
    ).resourceSpans[0].scopeSpans[0].spans as Array<Record<string, unknown>>
    expect(spans).toHaveLength(1)
    // New trace: never the untrusted trace id.
    expect(spans[0].traceId).not.toBe('4bf92f3577b34da6a3ce929d0e0e4736')
    expect(spans[0].links).toEqual([
      { traceId: '4bf92f3577b34da6a3ce929d0e0e4736', spanId: '00f067aa0ba902b7' },
    ])
    expect(spans[0].parentSpanId).toBeUndefined()
  })

  it('injects the active span context into outbound headers', async () => {
    const requests: Array<RequestInit> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(init ?? {})
        return new Response('{}', { status: 200 })
      }),
    )
    const { initObservability, runWithServerSpan, fetchWithSpan } =
      await loadModule()
    initObservability()

    await runWithServerSpan('http.server', {}, undefined, async () => {
      await fetchWithSpan(new URL('https://identity.example/oauth2/token'), {
        method: 'POST',
        headers: { accept: 'application/json' },
      })
    })

    const traceparent = new Headers(requests[0]?.headers).get('traceparent')
    expect(traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/)
  })

  it('emits key events independent of trace sampling', async () => {
    const posts: Array<{ url: string; body: Record<string, unknown> }> = []
    stubFetch(posts)
    const { initObservability, emitEvent, flush } = await loadModule()
    initObservability()

    emitEvent('login.callback.result', {
      outcome: 'success',
      category: 'audit',
    })
    await flush()

    expect(posts.some((post) => post.url.endsWith('/v1/logs'))).toBe(true)
  })

  it('drops instead of blocking when the queue is full', async () => {
    const posts: Array<{ url: string; body: Record<string, unknown> }> = []
    stubFetch(posts)
    const { initObservability, emitEvent, renderMetrics } = await loadModule()
    initObservability()

    for (let index = 0; index < 10_000; index += 1) {
      emitEvent('login.callback.result', { outcome: 'success' })
    }

    const metrics = renderMetrics()
    expect(metrics).toContain('identity_login_observability_logs_dropped_total')
    expect(Number(/logs_dropped_total (\d+)/.exec(metrics)?.[1])).toBeGreaterThan(0)
  })

  it('keeps merge semantics to one real exchange span', async () => {
    const posts: Array<{ url: string }> = []
    let resolveFetch: ((value: Response) => void) | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        posts.push({ url: String(input) })
        if (String(input).includes('/oauth2/token')) {
          return await new Promise<Response>((resolve) => {
            resolveFetch = resolve
          })
        }
        return new Response('{}', { status: 200 })
      }),
    )
    const { initObservability, flush } = await loadModule()
    initObservability()

    const { exchangeToken } = await import('./oauth.server')
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'code',
      redirect_uri: 'https://login.example/callback',
      code_verifier: 'verifier',
    })
    const first = exchangeToken(body, 'client', 'secret')
    const second = exchangeToken(body, 'client', 'secret')
    resolveFetch?.(
      new Response(JSON.stringify({ access_token: 'token' }), { status: 200 }),
    )
    await Promise.all([first, second])
    await flush()

    const tokenPosts = posts.filter((post) => post.url.includes('/oauth2/token'))
    expect(tokenPosts).toHaveLength(1)

    const tracePosts = posts.filter((post) => post.url.endsWith('/v1/traces'))
    const exchanged = tracePosts
      .map((post) => JSON.parse(String((post as { body?: unknown }).body ?? '{}')))
      .flatMap(
        (payload: {
          resourceSpans?: Array<{ scopeSpans: Array<{ spans: Array<{ name: string }> }> }>
        }) =>
          payload.resourceSpans?.flatMap((resource) =>
            resource.scopeSpans.flatMap((scope) => scope.spans),
          ) ?? [],
      )
      .filter((span) => span.name === 'token.exchange')
    expect(exchanged.length).toBeLessThanOrEqual(1)
  })

  it('renders bounded Prometheus metrics without business identifiers', async () => {
    const posts: Array<{ url: string; body: Record<string, unknown> }> = []
    stubFetch(posts)
    const { initObservability, renderMetrics, runWithServerSpan, withSpan } =
      await loadModule()
    initObservability()

    await runWithServerSpan(
      'http.server',
      { 'url.path': '/callback' },
      undefined,
      async () => {
        await withSpan('token.exchange.wait', 'internal', {}, async () => undefined)
      },
    )
    const metrics = renderMetrics()

    expect(metrics).toContain(
      'identity_login_observability_queue_depth{queue="spans"}',
    )
    expect(metrics).not.toContain('4bf92f3577b34da6a3ce929d0e0e4736')
  })

  it('ignores an invalid traceparent and still injects a fresh context', async () => {
    const posts: Array<{ url: string; body: Record<string, unknown> }> = []
    stubFetch(posts)
    const { initObservability, injectTraceHeaders, runWithServerSpan } =
      await loadModule()
    initObservability()

    const traceparent = await runWithServerSpan(
      'http.server',
      {},
      'not-a-traceparent',
      async () => injectTraceHeaders(new Headers()).get('traceparent'),
    )
    expect(traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-/)
  })

  it('disabled pipeline is a no-op', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    delete process.env.IDENTITY_LOGIN_OTLP_ENABLE
    const { initObservability, emitEvent, runWithServerSpan } = await loadModule()
    initObservability()
    emitEvent('login.callback.result', { outcome: 'success' })
    await runWithServerSpan('http.server', {}, undefined, async () => undefined)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('observability.server context isolation', () => {
  beforeEach(() => {
    process.env.IDENTITY_LOGIN_OTLP_ENABLE = 'true'
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'https://collector.example:4318'
    process.env.IDENTITY_LOGIN_TRACE_SAMPLE_RATIO = '1'
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    delete process.env.IDENTITY_LOGIN_OTLP_ENABLE
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT
    delete process.env.IDENTITY_LOGIN_TRACE_SAMPLE_RATIO
  })

  it('keeps concurrent request contexts separate', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('{}', { status: 200 })),
    )
    const { initObservability, runWithServerSpan, injectTraceHeaders } =
      await loadModule()
    initObservability()

    const read = (delay: number) =>
      runWithServerSpan('http.server', {}, undefined, async () => {
        await new Promise((resolve) => setTimeout(resolve, delay))
        return injectTraceHeaders(new Headers()).get('traceparent')
      })

    const [first, second] = await Promise.all([read(20), read(1)])
    expect(first).toBeTruthy()
    expect(second).toBeTruthy()
    expect(first).not.toBe(second)
    const firstTrace = first?.split('-')[1]
    const secondTrace = second?.split('-')[1]
    expect(firstTrace).not.toBe(secondTrace)
  })
})
