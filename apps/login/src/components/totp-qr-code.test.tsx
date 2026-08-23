// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { TotpQrCode } from './totp-qr-code'

const mocks = vi.hoisted(() => ({
  toString: vi.fn(),
}))

vi.mock('qrcode', () => ({
  default: { toString: mocks.toString },
}))

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('TotpQrCode', () => {
  it('generates the SVG in the browser from the complete otpauth URI', async () => {
    const uri = 'otpauth://totp/Identity:user%40example.com?secret=ABC&algorithm=SHA256&digits=6&period=30'
    mocks.toString.mockResolvedValue('<svg data-testid="generated-qr"></svg>')

    render(<TotpQrCode uri={uri} label="Authenticator QR code" />)

    expect((await screen.findByRole('img', { name: 'Authenticator QR code' })).innerHTML).toBe(
      '<svg data-testid="generated-qr"></svg>',
    )
    expect(mocks.toString).toHaveBeenCalledWith(uri, expect.objectContaining({
      type: 'svg',
      errorCorrectionLevel: 'M',
      margin: 0,
    }))
  })

  it('renders no broken QR when generation fails', async () => {
    mocks.toString.mockRejectedValue(new Error('unsupported URI'))

    render(<TotpQrCode uri="invalid" label="Authenticator QR code" />)

    await waitFor(() => expect(mocks.toString).toHaveBeenCalled())
    expect(screen.queryByRole('img')).toBeNull()
  })
})
