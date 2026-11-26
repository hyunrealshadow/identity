import { describe, expect, it } from 'vitest'

import { isSecureRequest } from './appearance.server'

describe('isSecureRequest', () => {
  it('treats local HTTP without forwarded HTTPS as insecure and HTTPS or forwarded HTTPS as secure', () => {
    expect(isSecureRequest(new Request('http://localhost:3000/appearance'))).toBe(false)
    expect(isSecureRequest(new Request('https://login.example.com/appearance'))).toBe(true)
    expect(
      isSecureRequest(
        new Request('http://localhost:3000/appearance', {
          headers: { 'x-forwarded-proto': 'https' },
        }),
      ),
    ).toBe(true)
  })
})
