import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { SettingsRow } from '#/components/settings-section'

describe('SettingsRow', () => {
  it('omits the extra body wrapper when conditional children all evaluate to empty', () => {
    const { container, rerender } = render(
      <SettingsRow label="Email sign-in" description="Allow email OTP sign-in">
        {false && <p>Needs delivery</p>}
        {null}
      </SettingsRow>,
    )

    expect(container.querySelector('.mt-3')).toBeNull()

    rerender(
      <SettingsRow label="Email sign-in" description="Allow email OTP sign-in">
        {false && <p>Needs delivery</p>}
        <p>Server error</p>
      </SettingsRow>,
    )

    const body = container.querySelector('.mt-3')
    expect(body).not.toBeNull()
    expect(body?.textContent).toBe('Server error')
  })
})
