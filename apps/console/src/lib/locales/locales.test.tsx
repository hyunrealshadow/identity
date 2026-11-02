import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { LanguageMenu } from '#/components/toolbar-controls'
import enUS from '#/lib/locales/en-US'
import zhCN from '#/lib/locales/zh-CN'
import { renderWithLocale } from '#/test/render'

function placeholders(message: string): string[] {
  const result: string[] = []
  let depth = 0
  let index = 0

  while (index < message.length) {
    const char = message[index]
    if (char === '{') {
      if (depth === 0) {
        let cursor = index + 1
        let token = ''
        while (cursor < message.length && /[A-Za-z0-9_]/.test(message[cursor])) {
          token += message[cursor]
          cursor += 1
        }
        if (token) result.push(token)
      }
      depth += 1
    } else if (char === '}' && depth > 0) {
      depth -= 1
    }
    index += 1
  }

  return result.sort()
}

describe('message catalogs', () => {
  it('have identical key sets and nonempty values', () => {
    const englishKeys = Object.keys(enUS).sort()
    const chineseKeys = Object.keys(zhCN).sort()
    expect(chineseKeys).toEqual(englishKeys)

    for (const key of englishKeys as Array<keyof typeof enUS>) {
      expect(enUS[key].trim().length).toBeGreaterThan(0)
      expect(zhCN[key].trim().length).toBeGreaterThan(0)
    }
  })

  it('have matching ICU placeholder variables', () => {
    for (const key of Object.keys(enUS) as Array<keyof typeof enUS>) {
      expect(placeholders(zhCN[key])).toEqual(placeholders(enUS[key]))
    }
  })

  it('renders the selected locale and switches language without reloading', async () => {
    const user = userEvent.setup()
    renderWithLocale(<LanguageMenu />, { locale: 'zh-CN' })

    const trigger = await screen.findByRole('button', { name: '语言: 简体中文' })
    await waitFor(() => expect(document.documentElement.lang).toBe('zh-CN'))

    await user.click(trigger)
    await user.click(await screen.findByRole('menuitem', { name: 'English' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Language: English' })).toBeTruthy()
      expect(document.documentElement.lang).toBe('en-US')
    })
  })
})
