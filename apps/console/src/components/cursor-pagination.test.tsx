import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'

import { CursorPagination } from '#/components/cursor-pagination'
import { clearAuthSession, setAuthSession } from '#/lib/auth/session'
import {
  useCursorPagination,
  type PageCursor,
} from '#/lib/use-cursor-pagination'
import { renderWithLocale } from '#/test/render'

afterEach(clearAuthSession)

function Fixture({
  filter = '',
  order = 'ASC',
  initial = {},
}: {
  filter?: string
  order?: string
  initial?: PageCursor
}) {
  const [cursor, setCursor] = useState(initial)
  const index = cursor.after
    ? Number(cursor.after) + 1
    : cursor.before
      ? Number(cursor.before) - 1
      : 1
  const controller = useCursorPagination({
    search: cursor,
    variables: {
      filter,
      order,
      ...(cursor.before
        ? { last: 10, before: cursor.before }
        : { first: 10, after: cursor.after }),
    },
    onNavigate: setCursor,
  })
  return (
    <>
      <output aria-label="Request">{JSON.stringify(cursor)}</output>
      <CursorPagination
        label="Results"
        pageCount={10}
        totalCount={200}
        controller={controller}
        pageInfo={{
          hasPreviousPage: index > 1,
          hasNextPage: index < 20,
          startCursor: String(index),
          endCursor: String(index),
        }}
      />
    </>
  )
}

describe('numbered cursor navigation', () => {
  it('does not reuse cursor history after switching principals', async () => {
    const user = userEvent.setup()
    const view = renderWithLocale(<Fixture />)
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    setAuthSession({
      accessToken: 'test-only',
      idToken: 'test-only',
      expiresAt: Date.now() + 60_000,
      scope: '',
      grantedScopes: [],
      claims: {
        sub: 'another-user',
        iss: 'https://example.test',
        aud: 'console',
        exp: 1,
      },
    })
    view.rerender(<Fixture />)
    expect(screen.queryByRole('button', { name: 'Go to page 2' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Go to page 1' }))
    expect(screen.getByLabelText('Request').textContent).toBe('{}')
  })
  it('keeps the first and discovered pages, and maps back/forward navigation to cursor directions', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Fixture />)
    expect(
      screen
        .getByRole('button', { name: 'Go to page 1' })
        .getAttribute('aria-current'),
    ).toBe('page')
    expect(screen.queryByRole('button', { name: 'Go to page 2' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    expect(
      screen
        .getByRole('button', { name: 'Go to page 3' })
        .getAttribute('aria-current'),
    ).toBe('page')
    await user.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(screen.getByLabelText('Request').textContent).toBe('{"before":"3"}')
    expect(
      screen
        .getByRole('button', { name: 'Go to page 2' })
        .getAttribute('aria-current'),
    ).toBe('page')
    await user.click(screen.getByRole('button', { name: 'Go to page 1' }))
    expect(screen.getByLabelText('Request').textContent).toBe('{}')
    await user.click(screen.getByRole('button', { name: 'Go to page 3' }))
    expect(screen.getByLabelText('Request').textContent).toBe('{"after":"2"}')
  })

  it('drops old numbered positions when the filter or ordering changes', async () => {
    const user = userEvent.setup()
    const view = renderWithLocale(<Fixture />)
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    expect(screen.getByRole('button', { name: 'Go to page 2' })).toBeTruthy()
    view.rerender(<Fixture filter="changed" />)
    expect(screen.queryByRole('button', { name: 'Go to page 2' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Go to page 1' }))
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    view.rerender(<Fixture filter="changed" order="DESC" />)
    expect(screen.queryByRole('button', { name: 'Go to page 2' })).toBeNull()
  })

  it('does not guess a deep-linked page number and always offers the real first page', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Fixture initial={{ after: '9' }} />, { locale: 'zh-CN' })
    expect(screen.queryByRole('button', { current: 'page' })).toBeNull()
    expect(screen.queryByRole('button', { name: '第 10 页' })).toBeNull()
    await user.click(screen.getByRole('button', { name: '第 1 页' }))
    expect(screen.getByLabelText('Request').textContent).toBe('{}')
    expect(
      screen
        .getByRole('button', { name: '第 1 页' })
        .getAttribute('aria-current'),
    ).toBe('page')
  })
})
