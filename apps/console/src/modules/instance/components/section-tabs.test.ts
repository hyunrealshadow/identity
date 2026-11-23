import { describe, expect, it } from 'vitest'

import { activeSectionTab, type SectionTab } from './section-tabs'

const email: SectionTab[] = [
  { to: '/email', label: 'emailTabDelivery' },
  { to: '/email/templates', label: 'emailTabTemplates' },
]

describe('section tabs', () => {
  it('keeps the section tab selected on its nested pages', () => {
    expect(activeSectionTab(email, '/console/email/templates/sign-in-code')).toBe('/email/templates')
    expect(activeSectionTab(email, '/console/email/templates/')).toBe('/email/templates')
  })

  it('selects the index tab on the area itself', () => {
    expect(activeSectionTab(email, '/console/email')).toBe('/email')
    expect(activeSectionTab(email, '/console/email/')).toBe('/email')
  })
})
