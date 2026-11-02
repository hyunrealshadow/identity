import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { DashboardScope } from '#/modules/dashboard/lib/dashboard-scope'
import type {
  InstanceOverview,
  RegistrationBucket,
} from '#/modules/dashboard/hooks/instance-dashboard'
import {
  InstanceDashboardView,
  NoManagementAccess,
} from '#/modules/dashboard/components/instance-dashboard-view'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { renderWithLocale } from '#/test/render'

function buckets(counts: ReadonlyArray<number>): RegistrationBucket[] {
  return counts.map((count, index) => ({
    date: `2026-10-${String(16 + index).padStart(2, '0')}`,
    count,
  }))
}

function overview(overrides: Partial<InstanceOverview> = {}): InstanceOverview {
  return {
    generatedAt: '2026-10-22T12:00:00.000Z',
    users: {
      total: 12,
      enabled: 10,
      createdLast7Days: 3,
      registrations: buckets([0, 1, 0, 2, 0, 0, 0]),
    },
    applications: { total: 4, enabled: 3, builtIn: 2 },
    sessions: { active: 8, createdLast24Hours: 5 },
    resources: { total: 2, enabled: 2 },
    ...overrides,
  }
}

function scope(overrides: Partial<DashboardScope> = {}): DashboardScope {
  return {
    users: true,
    applications: true,
    sessions: true,
    resources: true,
    hasAny: true,
    ...overrides,
  }
}

function issue(path: string): GraphQLIssue {
  return {
    message: `${path} unavailable`,
    path: ['instanceOverview', path],
    fields: [],
  }
}

describe('instance dashboard states', () => {
  it('keeps a real zero distinct from a module without access', () => {
    renderWithLocale(
      <InstanceDashboardView
        data={overview({
          users: {
            total: 0,
            enabled: 0,
            createdLast7Days: 0,
            registrations: buckets([0, 0, 0, 0, 0, 0, 0]),
          },
          applications: null,
        })}
        scope={scope({ applications: false })}
        issues={[]}
        partial={false}
        onRefresh={() => undefined}
      />,
    )

    const users = screen.getByRole('region', { name: 'Users' })
    expect(within(users).getByText('0')).toBeTruthy()

    const applications = screen.getByRole('region', { name: 'Applications' })
    expect(within(applications).getByText('No access')).toBeTruthy()
    expect(within(applications).queryByText('0')).toBeNull()
  })

  it('renders an honest empty trend without a chart', () => {
    renderWithLocale(
      <InstanceDashboardView
        data={overview({
          users: {
            total: 0,
            enabled: 0,
            createdLast7Days: 0,
            registrations: buckets([0, 0, 0, 0, 0, 0, 0]),
          },
        })}
        scope={scope()}
        issues={[]}
        partial={false}
        onRefresh={() => undefined}
      />,
    )

    expect(screen.getByText('No new users in the past 7 days')).toBeTruthy()
    expect(
      screen.queryByRole('img', { name: /New users, past 7 days/ }),
    ).toBeNull()
  })

  it('retains successful modules and retries a failed module', async () => {
    const user = userEvent.setup()
    const onRefresh = vi.fn()
    renderWithLocale(
      <InstanceDashboardView
        data={overview({ applications: null })}
        scope={scope()}
        issues={[issue('applications')]}
        partial
        onRefresh={onRefresh}
      />,
    )

    expect(screen.getByRole('region', { name: 'Users' }).textContent).toContain(
      '12',
    )
    expect(
      screen.getByText('Some overview data could not be loaded'),
    ).toBeTruthy()

    const applications = screen.getByRole('region', { name: 'Applications' })
    expect(within(applications).getByText('Not available')).toBeTruthy()
    expect(
      within(applications).getByText('applications unavailable'),
    ).toBeTruthy()
    expect(within(applications).queryByText('0')).toBeNull()

    await user.click(
      within(applications).getByRole('button', { name: 'Try again' }),
    )
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('localizes the management no-access boundary', () => {
    renderWithLocale(<NoManagementAccess />, { locale: 'zh-CN' })

    expect(screen.getByText('你无权访问实例管理')).toBeTruthy()
    expect(
      screen.getByText('如需更多权限，请联系能管理实例访问的用户'),
    ).toBeTruthy()
  })
})
