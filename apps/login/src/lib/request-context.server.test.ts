import { beforeEach, describe, expect, it, vi } from 'vitest'

import { forwardRequestContext } from './request-context.server'

const mocks = vi.hoisted(() => ({
  getRequestHeader: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
}))

describe('forwardRequestContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('forwards allowed context headers from the incoming request', () => {
    mocks.getRequestHeader.mockImplementation((name: string) => {
      if (name === 'user-agent') return 'Browser/1.0'
      if (name === 'x-forwarded-for') return '203.0.113.5'
      return undefined
    })

    const headers = forwardRequestContext(new Headers({ accept: 'application/json' }))

    expect(headers.get('accept')).toBe('application/json')
    expect(headers.get('user-agent')).toBe('Browser/1.0')
    expect(headers.get('x-forwarded-for')).toBe('203.0.113.5')
  })

  it('leaves headers unchanged when called outside a request StartEvent', () => {
    mocks.getRequestHeader.mockImplementation(() => {
      throw new Error('No StartEvent found in AsyncLocalStorage.')
    })

    const headers = forwardRequestContext(new Headers({ accept: 'application/json' }))

    expect(headers.get('accept')).toBe('application/json')
    expect(headers.get('user-agent')).toBeNull()
  })
})
