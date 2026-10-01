// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'

import { ScopeConsentStatus } from './scope-consent-status'

afterEach(cleanup)

it('marks previously allowed permissions with an accessible check', () => {
  const { container } = render(<ScopeConsentStatus granted locale="zh-CN" />)
  expect(screen.getByText('已同意')).toBeTruthy()
  expect(container.querySelector('svg')).toBeTruthy()
  expect(screen.getByText('已同意').className).toBe('sr-only')
})

it('does not show a marker for pending permissions', () => {
  const { container } = render(<ScopeConsentStatus granted={false} locale="zh-CN" />)
  expect(container.childElementCount).toBe(0)
})

it('does not invent a consent status when an older API omits it', () => {
  const { container } = render(<ScopeConsentStatus locale="zh-CN" />)
  expect(container.textContent).toBe('')
})

it('localizes the consent status', () => {
  render(<ScopeConsentStatus granted locale="en-US" />)
  expect(screen.getByText('Previously allowed')).toBeTruthy()
})
