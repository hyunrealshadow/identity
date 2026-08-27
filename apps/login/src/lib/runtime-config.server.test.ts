import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.resetModules()
})

const runtimeConfiguration = {
  version: 1,
  oauth_client: {
    client_id: '00000000-0000-0000-0000-000000000001',
    client_secret: 'current-secret-with-sufficient-entropy',
    generation: 1,
    expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
  },
  refresh_after: 60,
}

async function importModule() {
  return import('./runtime-config.server')
}

describe('login runtime configuration', () => {
  it('loads the runtime configuration through the internal API with the workload token', async () => {
    vi.stubEnv(
      'IDENTITY_WORKLOAD_TOKEN',
      '  workload-token-with-32-characters-minimum\n',
    )
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        new Response(JSON.stringify(runtimeConfiguration), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetch)

    const { loadOAuthClient } = await importModule()
    const client = await loadOAuthClient()

    expect(client).toEqual({
      client_id: runtimeConfiguration.oauth_client.client_id,
      client_secret: runtimeConfiguration.oauth_client.client_secret,
    })
    const [requestUrl, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(new URL(requestUrl).pathname).toBe(
      '/internal/workloads/self/runtime-configuration',
    )
    expect(new Headers(init.headers).get('authorization')).toBe(
      'Bearer workload-token-with-32-characters-minimum',
    )
  })

  it('reuses the in-memory snapshot within the refresh window', async () => {
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        new Response(JSON.stringify(runtimeConfiguration), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetch)

    const { loadOAuthClient } = await importModule()
    await loadOAuthClient()
    await loadOAuthClient()
    await loadOAuthClient()

    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('reports readiness from the current snapshot', async () => {
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        new Response(JSON.stringify(runtimeConfiguration), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetch)

    const { runtimeConfigurationReadiness } = await importModule()
    const readiness = await runtimeConfigurationReadiness()

    expect(readiness).toEqual({ ready: true })
  })

  it('reports unready when the runtime configuration is unavailable', async () => {
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response(null, { status: 503 }))
    vi.stubGlobal('fetch', fetch)

    const { runtimeConfigurationReadiness } = await importModule()
    const readiness = await runtimeConfigurationReadiness()

    expect(readiness).toEqual({ ready: false, reason: 'no-runtime-configuration' })
  })

  it('refuses to use an expired OAuth client snapshot', async () => {
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const expired = {
      ...runtimeConfiguration,
      oauth_client: {
        ...runtimeConfiguration.oauth_client,
        expires_at: new Date(Date.now() - 1).toISOString(),
      },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        new Response(JSON.stringify(expired), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    )

    const { loadOAuthClient, runtimeConfigurationReadiness } = await importModule()

    await expect(loadOAuthClient()).rejects.toThrow('secret-expired')
    await expect(runtimeConfigurationReadiness()).resolves.toEqual({
      ready: false,
      reason: 'secret-expired',
    })
  })

  it('fails closed when a cached configuration is stale and refresh fails', async () => {
    vi.useFakeTimers()
    const now = new Date('2026-01-01T00:00:00Z')
    vi.setSystemTime(now)
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const value = {
      ...runtimeConfiguration,
      oauth_client: {
        ...runtimeConfiguration.oauth_client,
        expires_at: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      },
    }
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(value), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
      .mockResolvedValue(new Response(null, { status: 503 }))
    vi.stubGlobal('fetch', fetch)
    const { loadOAuthClient, runtimeConfigurationReadiness } = await importModule()
    await loadOAuthClient()

    vi.setSystemTime(new Date(now.getTime() + 6 * 60 * 1000))

    await expect(loadOAuthClient()).rejects.toThrow('runtime-configuration-stale')
    await expect(runtimeConfigurationReadiness()).resolves.toEqual({
      ready: false,
      reason: 'runtime-configuration-stale',
    })
  })

  it('treats a malformed secret expiry as unready', async () => {
    vi.stubEnv('IDENTITY_WORKLOAD_TOKEN', 'workload-token-with-32-characters-minimum')
    vi.stubEnv('IDENTITY_INTERNAL_API_URL', 'https://identity.internal:5151')
    const malformed = {
      ...runtimeConfiguration,
      oauth_client: {
        ...runtimeConfiguration.oauth_client,
        expires_at: 'not-a-date',
      },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        new Response(JSON.stringify(malformed), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    )

    const { runtimeConfigurationReadiness } = await importModule()

    await expect(runtimeConfigurationReadiness()).resolves.toEqual({
      ready: false,
      reason: 'invalid-secret-expiry',
    })
  })
})
