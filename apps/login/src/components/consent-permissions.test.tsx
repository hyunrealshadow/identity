// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'

import { ConsentPermissions } from './consent-permissions'

afterEach(cleanup)

it('uses configured localized descriptions and falls back to the default description', () => {
  const scopes = [{
    name: 'profile',
    display_name: 'Configured profile',
    description: 'Custom default description',
    descriptions: { 'zh-CN': '数据库配置的个人资料说明' },
    essential: false,
  }]
  const { rerender } = render(<ConsentPermissions scopes={scopes} locale="zh-CN" />)
  expect(screen.getByText('Configured profile')).toBeTruthy()
  expect(screen.getByText('数据库配置的个人资料说明')).toBeTruthy()

  rerender(<ConsentPermissions scopes={scopes} locale="en-US" />)
  expect(screen.getByText('Custom default description')).toBeTruthy()
})
