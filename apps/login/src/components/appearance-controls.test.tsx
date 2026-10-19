// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AppearanceControls } from './appearance-controls'

const router = vi.hoisted(() => ({
  state: {
    location: { href: '/login/password?login_id=opaque' },
    matches: [{ loaderData: { uiLocales: 'zh-CN' } }],
  },
}))

vi.mock('@tanstack/react-router', () => ({
  useRouterState: ({ select }: { select: (state: typeof router.state) => unknown }) => select(router.state),
}))

beforeEach(() => {
  router.state.location.href = '/login/password?login_id=opaque'
  vi.stubGlobal('matchMedia', () => ({ addEventListener: vi.fn(), removeEventListener: vi.fn() }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('selects browser mode without a URL preference even when the page is Chinese', () => {
  render(<AppearanceControls locale="zh-CN" />)
  expect(screen.getByRole('button', { name: '语言: 跟随浏览器' })).toBeTruthy()
  expect(screen.getByRole('link', { name: '跟随浏览器' }).querySelector('svg')).toBeTruthy()
  expect(screen.getByRole('link', { name: '简体中文' }).querySelector('svg')).toBeNull()
})

it('removes every ui_locales parameter while preserving the login context and fragment', () => {
  router.state.location.href = '/login/password?login_id=opaque&ui_locales=zh-CN&restart=required&ui_locales=en-US#credential'
  render(<AppearanceControls locale="zh-CN" />)
  expect(screen.getByRole('button', { name: '语言: 简体中文' })).toBeTruthy()
  expect(screen.getByRole('link', { name: '跟随浏览器' }).getAttribute('href'))
    .toBe('/login/password?login_id=opaque&restart=required#credential')
  expect(screen.getByRole('link', { name: 'English' }).getAttribute('href'))
    .toBe('/login/password?login_id=opaque&ui_locales=en-US&restart=required#credential')
})
