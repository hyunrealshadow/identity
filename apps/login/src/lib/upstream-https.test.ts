import { describe, expect, it } from 'vitest'

import { forwardedProtoIsHttps } from './upstream-https'

describe('forwardedProtoIsHttps', () => {
  it('accepts X-Forwarded-Proto from an HTTPS upstream', () => {
    expect(
      forwardedProtoIsHttps(
        new Headers({ 'x-forwarded-proto': 'https, http' }),
      ),
    ).toBe(true)
  })

  it('accepts the standardized Forwarded header', () => {
    expect(
      forwardedProtoIsHttps(
        new Headers({ forwarded: 'for=192.0.2.1;proto="HTTPS";host=id.example' }),
      ),
    ).toBe(true)
  })

  it('rejects missing and insecure forwarding metadata', () => {
    expect(forwardedProtoIsHttps(new Headers())).toBe(false)
    expect(
      forwardedProtoIsHttps(new Headers({ 'x-forwarded-proto': 'http' })),
    ).toBe(false)
    expect(
      forwardedProtoIsHttps(
        new Headers({
          'x-forwarded-proto': 'http',
          forwarded: 'proto=https',
        }),
      ),
    ).toBe(false)
  })
})
