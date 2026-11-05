import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ResourceTable } from '#/components/resource-table'
import type {
  ConsoleUsersQuery,
  ConsoleUsersQueryVariables,
} from '#/generated/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { renderHookWithLocale, renderWithLocale } from '#/test/render'
import { useUsers } from './use-users'

const mocks = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('#/lib/graphql/use-graphql', () => ({
  useGraphQL: () => mocks.request,
}))

const variables: ConsoleUsersQueryVariables = { first: 10 }

function result(username: string): GraphQLResult<ConsoleUsersQuery> {
  return {
    data: {
      users: {
        totalCount: 8,
        pageInfo: {
          hasNextPage: true,
          hasPreviousPage: false,
          startCursor: 'start',
          endCursor: 'end',
        },
        edges: [
          {
            cursor: 'end',
            node: {
              id: 'user-one',
              username,
              email: 'user@example.test',
              emailVerified: true,
              enabled: true,
              locked: false,
              lockedUntil: null,
              failedAttempts: 0,
              version: 'lock',
              createdAt: '2026-01-01T00:00:00Z',
              updatedAt: null,
            },
          },
        ],
      },
    },
    errors: [],
    partial: false,
    forbidden: false,
    unauthorized: false,
  }
}

function deferred() {
  let resolve!: (value: GraphQLResult<ConsoleUsersQuery>) => void
  const promise = new Promise<GraphQLResult<ConsoleUsersQuery>>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

function Fixture() {
  const users = useUsers(variables, true)
  if (!users.data) return <p>{users.status}</p>
  return (
    <ResourceTable
      id="refresh-test"
      label="Users"
      items={users.data.edges.map((edge) => edge.node)}
      columns={[
        {
          id: 'name',
          label: 'Name',
          primary: true,
          render: (row) => row.username,
        },
      ]}
      refreshing={users.refreshing}
      onRefresh={() => void users.refresh()}
      onOrderChange={() => {}}
      pagination={<p>Page 1 - Total {users.data.totalCount}</p>}
    />
  )
}

describe('user list refresh', () => {
  it('keeps the table header and footer mounted and shows skeleton rows until new data arrives', async () => {
    const pending = deferred()
    mocks.request
      .mockResolvedValueOnce(result('Ada'))
      .mockReturnValueOnce(pending.promise)
    const user = userEvent.setup()
    renderWithLocale(<Fixture />)
    await screen.findByText('Ada')
    const header = screen.getByRole('columnheader', { name: 'Name' })
    const footer = screen.getByText('Page 1 - Total 8')
    const refresh = screen.getByRole('button', { name: 'Refresh table' })

    await user.click(refresh)
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBe(header)
    expect(screen.getByText('Page 1 - Total 8')).toBe(footer)
    expect(screen.getByRole('button', { name: 'Refresh table' })).toBe(refresh)
    expect(refresh.hasAttribute('disabled')).toBe(true)
    expect(
      screen.getByRole('button', { name: 'Table preferences' }),
    ).toBeTruthy()
    expect(
      screen.getByRole('region', { name: 'Users', busy: true }),
    ).toBeTruthy()
    expect(screen.getByRole('status').textContent).toBe('Loading table data')
    expect(screen.queryByText('Ada')).toBeNull()
    await act(async () => pending.resolve(result('Grace')))
    expect(await screen.findByText('Grace')).toBeTruthy()
    expect(
      screen.queryByRole('region', { name: 'Users', busy: true }),
    ).toBeNull()
    expect(refresh.hasAttribute('disabled')).toBe(false)
  })

  it('clears old data on a filter change and ignores a previous refresh response', async () => {
    const refresh = deferred(),
      filtered = deferred()
    mocks.request
      .mockResolvedValueOnce(result('Ada'))
      .mockReturnValueOnce(refresh.promise)
      .mockReturnValueOnce(filtered.promise)
    const { result: state, rerender } = renderHookWithLocale(
      ({ query }) => useUsers(query, true),
      {
        initialProps: { query: variables },
      },
    )
    await waitFor(() => expect(state.current.data).not.toBeNull())
    let refreshing!: Promise<void>
    act(() => {
      refreshing = state.current.refresh()
    })
    await waitFor(() => expect(state.current.refreshing).toBe(true))
    rerender({ query: { first: 10, filter: { query: 'other' } } })
    expect(state.current.data).toBeNull()
    expect(state.current.refreshing).toBe(false)
    await act(async () => {
      refresh.resolve(result('stale'))
      await refreshing
    })
    expect(state.current.data).toBeNull()
    await act(async () =>
      filtered.resolve({ ...result('unused'), data: null, forbidden: true }),
    )
    await waitFor(() => expect(state.current.status).toBe('error'))
    expect(state.current.forbidden).toBe(true)
    expect(state.current.data).toBeNull()
  })
})
