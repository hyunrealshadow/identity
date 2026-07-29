import { describe, expect, it } from 'vitest'

import { formErrorResponse, navigationResponse } from './responses.server'

describe('progressive form responses', () => {
  it('uses a 303 redirect for native form submissions', () => {
    const request = new Request('https://login.example.com/login', {
      method: 'POST',
    })

    const response = navigationResponse(request, '/login/challenge')

    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/login/challenge')
  })

  it('returns navigation JSON for enhanced form submissions', async () => {
    const request = new Request('https://login.example.com/login', {
      method: 'POST',
      headers: { 'x-enhanced-form': '1' },
    })

    const response = navigationResponse(request, '/login/challenge')

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({
      redirect: '/login/challenge',
    })
  })

  it('keeps errors and form context out of the redirect URL', () => {
    const request = new Request('https://login.example.com/login', {
      method: 'POST',
    })

    const response = formErrorResponse(
      request,
      '/login',
      'Invalid account',
      { login_id: 'protected-login', identifier: 'alice' },
    )
    const destination = new URL(response.headers.get('location') ?? '')

    expect(destination.pathname).toBe('/login')
    expect(destination.search).toBe('')
    expect(response.headers.get('set-cookie')).toContain('HttpOnly')
    expect(response.headers.get('set-cookie')).toContain('Secure')
    expect(response.headers.get('set-cookie')).toContain('SameSite=Lax')
    expect(response.headers.get('set-cookie')).toContain('Max-Age=60')
  })
})
