import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  finishAuthorization: vi.fn(),
  setResponseStatus: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  setResponseStatus: mocks.setResponseStatus,
}))

vi.mock('#/lib/oauth.server', () => ({
  finishAuthorization: mocks.finishAuthorization,
}))

import { handleCallbackGet } from './callback-route.server'

describe('callback GET handler', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the SSR error page in place with status 400 for HTML requests', async () => {
    mocks.finishAuthorization.mockResolvedValue(
      new Response('The authorization response is invalid or has expired.', {
        status: 400,
      }),
    )
    const nextResult = { isNext: true as const, context: undefined }
    const next = vi.fn(() => nextResult)

    const result = await handleCallbackGet({
      request: new Request('https://identity.example/callback?code=stale&state=expired', {
        headers: { accept: 'text/html,application/xhtml+xml' },
      }),
      next,
    })

    expect(mocks.setResponseStatus).toHaveBeenCalledWith(400)
    expect(next).toHaveBeenCalledOnce()
    expect(result).toBe(nextResult)
  })

  it('renders the SSR error page in place when Accept header is omitted', async () => {
    mocks.finishAuthorization.mockResolvedValue(
      new Response('invalid', { status: 400 }),
    )
    const nextResult = { isNext: true as const, context: undefined }
    const next = vi.fn(() => nextResult)

    const result = await handleCallbackGet({
      request: new Request('https://identity.example/callback?state=expired'),
      next,
    })

    expect(mocks.setResponseStatus).toHaveBeenCalledWith(400)
    expect(next).toHaveBeenCalledOnce()
    expect(result).toBe(nextResult)
  })

  it('returns the plain 400 response directly for non-HTML requests', async () => {
    const errorResponse = new Response('invalid', { status: 400 })
    mocks.finishAuthorization.mockResolvedValue(errorResponse)
    const next = vi.fn()

    const result = await handleCallbackGet({
      request: new Request('https://identity.example/callback?state=expired', {
        headers: { accept: 'application/json' },
      }),
      next,
    })

    expect(mocks.setResponseStatus).not.toHaveBeenCalled()
    expect(next).not.toHaveBeenCalled()
    expect(result).toBe(errorResponse)
  })

  it.each([200, 302])('returns status %i responses without invoking SSR fallback', async (status) => {
    const response = new Response(status === 200 ? 'ok' : null, { status })
    mocks.finishAuthorization.mockResolvedValue(response)
    const next = vi.fn()

    const result = await handleCallbackGet({
      request: new Request('https://identity.example/callback?code=valid&state=valid', {
        headers: { accept: 'text/html' },
      }),
      next,
    })

    expect(mocks.setResponseStatus).not.toHaveBeenCalled()
    expect(next).not.toHaveBeenCalled()
    expect(result).toBe(response)
  })
})
