import { describe, expect, it } from 'vitest'

import {
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from './responses.server'

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

  it('preserves the RP login context while keeping errors and identifiers out of the URL', () => {
    const request = new Request('https://login.example.com/login', {
      method: 'POST',
    })

    const response = formErrorResponse(
      request,
      '/login',
      'Invalid account',
      { login_id: 'protected-login', identifier: 'alice' },
    )
    const destination = new URL(
      response.headers.get('location') ?? '',
      request.url,
    )

    expect(destination.pathname).toBe('/login')
    expect(destination.searchParams.get('login_id')).toBe('protected-login')
    expect([...destination.searchParams.keys()]).toEqual(['login_id'])
    expect(response.headers.get('set-cookie')).toContain('HttpOnly')
    expect(response.headers.get('set-cookie')).toContain('Secure')
    expect(response.headers.get('set-cookie')).toContain('SameSite=Lax')
    expect(response.headers.get('set-cookie')).toContain('Max-Age=60')
  })

  it('does not expose the enhanced handler internal origin', async () => {
    const request = new Request('http://127.0.0.1:53662/login', {
      method: 'POST',
      headers: { 'x-enhanced-form': '1' },
    })

    const response = formErrorResponse(
      request,
      '/login',
      'Invalid account',
      { login_id: 'protected-login' },
    )

    await expect(response.json()).resolves.toMatchObject({
      redirect: '/login?login_id=protected-login',
    })
  })

  it.each([false, true])('preserves login context for field validation errors (enhanced=%s)', async (enhanced) => {
    const request = new Request('https://login.example.com/login', {
      method: 'POST',
      headers: enhanced ? { 'x-enhanced-form': '1' } : {},
    })
    const response = formValidationErrorResponse(
      request,
      '/login',
      'Unknown username',
      { login_id: 'rp+login/id', identifier: 'wrong-user' },
      { identifier: 'Unknown username' },
    )
    const destination = enhanced
      ? (await response.json()).redirect
      : response.headers.get('location')
    expect(destination).toBe('/login?login_id=rp%2Blogin%2Fid')
  })

  it('preserves an explicit challenge retry destination', () => {
    const request = new Request('https://login.example.com/login/challenge', { method: 'POST' })
    const destination = '/login/challenge?login_id=rp-login&credential_type=otp&restart=required'
    const response = formErrorResponse(request, '/login/challenge', 'Retry',
      { login_id: 'rp-login' }, undefined, destination)
    expect(response.headers.get('location')).toBe(destination)
  })

  it('stores multiple field errors in the flash cookie', () => {
    const request = new Request('https://login.example.com/install', {
      method: 'POST',
    })

    const response = formValidationErrorResponse(
      request,
      '/install',
      'Check the form for errors.',
      { username: '', email: 'invalid' },
      {
        username: 'Username is required.',
        email: 'The email address is invalid.',
      },
    )
    const cookie = response.headers.get('set-cookie') ?? ''
    expect(response.headers.get('location')).toBe('/install')
    const encoded = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? ''
    const flash = JSON.parse(decodeURIComponent(encoded))

    expect(flash.fields).toEqual({
      username: 'Username is required.',
      email: 'The email address is invalid.',
    })
  })
})
