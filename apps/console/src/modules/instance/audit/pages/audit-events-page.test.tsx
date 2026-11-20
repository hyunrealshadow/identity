import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import type { EffectivePermissions } from '#/lib/workspace'
import {
  ALL_AUDIT_LOG,
  AUDIT_CATEGORY_LOGS,
} from '#/modules/instance/audit/lib/audit-logs'
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
              category: 'MANAGEMENT',
              action: 'ROLE_UPDATE',
              outcome: 'SUCCESS',
              failureReason: null,
              actor: {
                kind: 'USER',
                id: 'VXNlcjo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
                oid: '550e8400-e29b-41d4-a716-446655440000',
                label: 'alice',
                user: {
                  id: 'VXNlcjo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
                  username: 'alice',
                  email: 'alice@example.test',
                  nickname: 'Alice Operator',
                },
                client: null,
              },
              target: {
                kind: 'ROLE',
                id: 'Um9sZTo2NjBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDE',
                oid: '660e8400-e29b-41d4-a716-446655440001',
                label: 'Auditors',
              },
              clientId: null,
              authMethods: [],
              ipAddress: '203.0.113.7',
              userAgent: 'Mozilla/5.0 Test',
              requestId: 'req-audit-1',
              traceId: 'trace-audit-1',
              changes: [
                {
                  field: 'NAME',
                  kind: 'VALUE',
                  oldValue: 'Readers',
                  newValue: 'Auditors',
                  added: [],
                  removed: [],
                },
              ],
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

    renderWithLocale(<AuditEventsPage log={ALL_AUDIT_LOG} search={{}} />)

    expect(screen.getByText('Audit log is not available')).toBeTruthy()
    expect(mocks.eventsCalls.every((call) => !call.enabled)).toBe(true)
  })

  it('gates actorUser and actorClient inclusions by caller read scopes and opens detail drawer', async () => {
    mocks.permissions = permissions(['management.audit.read'])

    const view = renderWithLocale(
      <AuditEventsPage
        log={ALL_AUDIT_LOG}
        search={{
          event: 'QXVkaXRFdmVudDo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
        }}
      />,
    )

    expect(mocks.eventsCalls.at(-1)?.variables).toMatchObject({
      includeActorUser: false,
      includeActorClient: false,
    })

    // The recorded name stands in for the account the caller cannot read,
    // and the drawer shows what changed.
    expect(screen.getAllByText('alice').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Readers')).toBeTruthy()
    expect(screen.getByText('Mozilla/5.0 Test')).toBeTruthy()

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

    renderWithLocale(<AuditEventsPage log={ALL_AUDIT_LOG} search={{}} />)

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

    renderWithLocale(<AuditEventsPage log={ALL_AUDIT_LOG} search={{ q: 'targetKind:' }} />)

    expect(mocks.eventsCalls.length).toBeGreaterThan(0)
    expect(mocks.eventsCalls.every((call) => call.variables === null)).toBe(true)
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('targetKind:')
    expect(screen.getByText('The query has errors')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  it('navigates with event parameter when clicking a row action title button', async () => {
    mocks.permissions = permissions(['management.audit.read', 'management.user.read'])

    renderWithLocale(<AuditEventsPage log={ALL_AUDIT_LOG} search={{}} />)

    const rowActionButton = screen.getByRole('button', {
      name: 'Alice Operator Updated role Auditors',
    })
    fireEvent.click(rowActionButton)

    await waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalled()
    })
    const navArg = mocks.navigate.mock.calls.at(-1)?.[0]
    expect(navArg.search.event).toBe(
      'QXVkaXRFdmVudDo1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDA',
    )
  })

  it('queries only its own category and keeps navigation on its route', async () => {
    mocks.permissions = permissions(['management.audit.read'])
    const log = AUDIT_CATEGORY_LOGS.SIGN_IN

    renderWithLocale(<AuditEventsPage log={log} search={{}} />)

    expect(screen.getByRole('heading', { name: 'Sign-ins', level: 1 })).toBeTruthy()
    expect(mocks.eventsCalls.at(-1)?.variables).toMatchObject({ category: 'SIGN_IN' })
    fireEvent.click(screen.getByRole('button', { name: '24h' }))
    await waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalled()
    })
    expect(mocks.navigate.mock.calls.at(-1)?.[0].to).toBe('/audit-events/sign-in')
  })
})
