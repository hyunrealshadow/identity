// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'

import { ConsentPermissions } from './consent-permissions'

afterEach(cleanup)

it('uses configured localized names and descriptions with scalar fallback', () => {
  const scopes = [{
    code: 'profile',
    name: 'Configured profile',
    names: { 'zh-CN': '个人资料' },
    description: 'Custom default description',
    descriptions: { 'zh-CN': '数据库配置的个人资料说明' },
    essential: false,
  }]
  const { rerender } = render(<ConsentPermissions scopes={scopes} locale="zh-CN" />)
  expect(screen.getByText('个人资料')).toBeTruthy()
  expect(screen.getByText('数据库配置的个人资料说明')).toBeTruthy()

  rerender(<ConsentPermissions scopes={scopes} locale="en-US" />)
  expect(screen.getByText('Configured profile')).toBeTruthy()
  expect(screen.getByText('Custom default description')).toBeTruthy()

  rerender(<ConsentPermissions scopes={[{ ...scopes[0], names: {}, descriptions: {} }]} locale="en-US" />)
  expect(screen.getByText('Configured profile')).toBeTruthy()
  expect(screen.getByText('Custom default description')).toBeTruthy()
})

it('uses matching parent translations and falls back to independent defaults', () => {
  const { rerender } = render(<ConsentPermissions scopes={[{
    code: 'custom.read',
    name: '',
    names: { zh: '读取数据', 'en-US': 'Read data' },
    descriptions: { 'en-US': 'View your data' },
    description: '',
    essential: false,
  }]} locale="zh-CN" />)
  expect(screen.getByText('读取数据')).toBeTruthy()
  expect(screen.queryByText('View your data')).toBeNull()

  rerender(<ConsentPermissions scopes={[{
    code: 'custom.read',
    name: '',
    names: { 'zh-CN': ' ' },
    description: '',
    essential: false,
  }]} locale="zh-CN" />)
  expect(screen.getByText('custom.read')).toBeTruthy()

  rerender(<ConsentPermissions scopes={[{
    code: 'custom.read',
    name: '',
    names: { 'fr-FR': 'Lire les données' },
    description: '',
    essential: false,
  }]} locale="en-US" />)
  expect(screen.getByText('custom.read')).toBeTruthy()
})
