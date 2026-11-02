import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { StepUpPanel } from '#/components/step-up-panel'
import { LocaleTestProvider } from '#/test/render'

const auth = vi.hoisted(() => ({
  requireReauthentication: vi.fn(),
  reauthenticationPopup: null as object | null,
}))
vi.mock('#/lib/auth/context', () => ({ useAuth: () => auth }))
beforeEach(() => { auth.requireReauthentication.mockReset(); auth.reauthenticationPopup = null })

describe('retained authentication feedback', () => {
  it('clears managed feedback after completion or cancellation, including a remount', () => {
    const stepUp = { source: 'preflight' as const, recoveryManaged: true, maxAge: 300 }
    auth.reauthenticationPopup = { phase: 'waiting' }
    const view = render(<LocaleTestProvider><StepUpPanel stepUp={stepUp} /></LocaleTestProvider>)
    expect(screen.getByText('Signing in again')).toBeTruthy()
    auth.reauthenticationPopup = null
    view.rerender(<LocaleTestProvider><StepUpPanel stepUp={stepUp} /></LocaleTestProvider>)
    expect(screen.queryByText('Signing in again')).toBeNull()
    view.unmount()
    render(<LocaleTestProvider><StepUpPanel stepUp={stepUp} /></LocaleTestProvider>)
    expect(screen.queryByText('Signing in again')).toBeNull()
    expect(auth.requireReauthentication).not.toHaveBeenCalled()
  })

  it('still coordinates an unhandled policy challenge once', () => {
    render(<LocaleTestProvider><StepUpPanel stepUp={{ source: 'graphql', acrValues: 'aal2' }} /></LocaleTestProvider>)
    expect(auth.requireReauthentication).toHaveBeenCalledTimes(1)
  })
})
