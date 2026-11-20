import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import type { EffectivePermissions } from '#/lib/workspace'
import { AuditEventsPage } from '#/modules/instance/audit/pages/audit-events-page'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({
  permissions: {} as EffectivePermissions,
  navigate: vi.fn(),
  eventsCalls: [] as Array<{ variables: unknown; enabled: boolean }>,
  eventsResult: {
    status: 'ready' as const,
    refreshing: false,
    forbidden: false,
    failure: null,
    stepUp: null,
    errors: [],
    requestId: undefined as string | undefined,
    traceId: undefined as string | undefined,
    refresh: vi.fn(),
    data: {
      auditEvents: {
        totalCount: 1,
        pageInfo: {
          hasPreviousPage: false,
          hasNextPage: false,
          startCursor: 'c1',
          endCursor: 'c1',
        },
        edges: [
          {
            cursor: 'c1',
            node: {
              id: 'QXVkaXRFdmVudDo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
              occurredAt: '2026-11-20T09:15:00Z',
              transactionId: '42',
              action: 'user.create',
              operation: 'mutation',
              eventKind: 'semantic',
              actorType: 'user',
              actorOid: '550e8400-e29b-41d4-a716-446655440000',
              actorGlobalId: 'VXNlcjo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
              targetType: 'user',
              targetOid: '660e8400-e29b-41d4-a716-446655440001',
              targetGlobalId: 'VXNlcjo2NjBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDE',
              resourceType: 'user',
              resourceOid: '660e8400-e29b-41d4-a716-446655440001',
              resourceGlobalId: 'VXNlcjo2NjBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDE',
              subjectOid: null,
              subjectGlobalId: null,
              status: 'success',
              previousStatus: null,
              credentialType: null,
              reason: 'Provisioned operator account',
              requestId: 'req-audit-1',
              traceId: 'trace-audit-1',
              actorUser: {
                id: 'VXNlcjo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
                username: 'alice',
                email: 'alice@example.test',
                nickname: 'Alice Operator',
              },
              actorClient: null,
            },
          },
        ],
      },
    },
  },
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mocks.navigate,
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}))

vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({ claims: { sub: 'operator', iss: 'https://id.example.test' } }),
}))

vi.mock('#/lib/auth/session', () => ({
  getAuthSession: () => ({ claims: { sub: 'operator', iss: 'https://id.example.test' } }),
}))

vi.mock('#/lib/workspace', () => ({
  useWorkspace: () => ({
    status: 'ready',
    data: { effectivePermissions: mocks.permissions },
    refresh: vi.fn(),
  }),
}))

vi.mock('#/modules/instance/audit/hooks/use-audit-events', () => ({
  useAuditEvents: (variables: unknown, enabled: boolean) => {
    mocks.eventsCalls.push({ variables, enabled })
    // Like useConsoleQuery: no variables means no request and no data.
    return variables
      ? mocks.eventsResult
      : { ...mocks.eventsResult, status: 'idle', data: null }
  },
  useAuditEventDetail: () => ({
    status: 'idle',
    refreshing: false,
    forbidden: false,
    failure: null,
    stepUp: null,
    errors: [],
    data: null,
    refresh: vi.fn(),
  }),
  useAuditEventActions: () => ({
    status: 'ready',
    data: { auditEventActions: ['user.create', 'client.update'] },
  }),
}))

function permissions(effective: string[]): EffectivePermissions {
  return {
    effectiveScopes: effective,
    requestableScopes: [],
    grantedScopes: [],
    authentication: {
      acr: 'urn:identity:aal2',
      authTime: null,
      aal2: true,
      recent: true,
    },
  }
}

describe('AuditEventsPage', () => {
  beforeEach(() => {
    mocks.navigate.mockReset()
    mocks.eventsCalls.length = 0
  })

  it('denies view when management.audit.read is missing', () => {
    mocks.permissions = permissions(['management.user.read'])

    renderWithLocale(<AuditEventsPage search={{}} />)

    expect(screen.getByText('Audit events are not available')).toBeTruthy()
    expect(mocks.eventsCalls.every((call) => !call.enabled)).toBe(true)
  })

  it('gates actorUser and actorClient inclusions by caller read scopes and opens detail drawer', async () => {
    mocks.permissions = permissions(['management.audit.read'])

    const view = renderWithLocale(
      <AuditEventsPage
        search={{
          event: 'QXVkaXRFdmVudDo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
        }}
      />,
    )

    expect(mocks.eventsCalls.at(-1)?.variables).toMatchObject({
      includeActorUser: false,
      includeActorClient: false,
    })

    expect(screen.getByText('Provisioned operator account')).toBeTruthy()
    expect(screen.getAllByText('Alice Operator').length).toBeGreaterThanOrEqual(1)

    const filterByActor = screen.getByRole('button', { name: 'Filter by actor' })
    fireEvent.click(filterByActor)

    await waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalled()
    })
    const navArg = mocks.navigate.mock.calls.at(-1)?.[0]
    expect(navArg.search.q).toContain('actor:550e8400-e29b-41d4-a716-446655440000')
    expect(navArg.search.event).toBeUndefined()

    view.unmount()
  })

  it('includes actorUser and actorClient when caller holds both read scopes and applies quick preset', async () => {
    mocks.permissions = permissions([
      'management.audit.read',
      'management.user.read',
      'management.client.read',
    ])

    renderWithLocale(<AuditEventsPage search={{}} />)

    expect(mocks.eventsCalls.at(-1)?.variables).toMatchObject({
      includeActorUser: true,
      includeActorClient: true,
    })

    const preset24h = screen.getByRole('button', { name: '24h' })
    fireEvent.click(preset24h)

    await waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalled()
    })
    const navArg = mocks.navigate.mock.calls.at(-1)?.[0]
    expect(navArg.search.q).toBe('occurredAt:[now-24h TO now]')
  })

  it('does not send an invalid query opened from a link and explains it at the query bar', () => {
    mocks.permissions = permissions(['management.audit.read'])

    renderWithLocale(<AuditEventsPage search={{ q: 'targetType:' }} />)

    expect(mocks.eventsCalls.length).toBeGreaterThan(0)
    expect(mocks.eventsCalls.every((call) => call.variables === null)).toBe(true)
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('targetType:')
    expect(screen.getByText('The query has errors')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  it('navigates with event parameter when clicking a row action title button', async () => {
    mocks.permissions = permissions(['management.audit.read'])

    renderWithLocale(<AuditEventsPage search={{}} />)

    const rowActionButton = screen.getByRole('button', { name: 'user.create' })
    fireEvent.click(rowActionButton)

    await waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalled()
    })
    const navArg = mocks.navigate.mock.calls.at(-1)?.[0]
    expect(navArg.search.event).toBe(
      'QXVkaXRFdmVudDo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
    )
  })
})
