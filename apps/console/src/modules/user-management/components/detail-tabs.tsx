import { Link } from '@tanstack/react-router'
import type { LucideIcon } from 'lucide-react'
import { Info, KeyRound, Shield, UserRound, UsersRound } from 'lucide-react'

import { useTranslator, type MessageKey } from '#/lib/i18n'

interface DetailTab {
  label: MessageKey
  to:
    | '/users/$userId'
    | '/users/$userId/groups'
    | '/users/$userId/roles'
    | '/users/$userId/permissions'
    | '/roles/$roleId'
    | '/roles/$roleId/permissions'
    | '/roles/$roleId/users'
    | '/roles/$roleId/groups'
    | '/groups/$groupId'
    | '/groups/$groupId/members'
    | '/groups/$groupId/roles'
  icon: LucideIcon
}

function DetailTabNav({
  ariaLabel,
  tabs,
  params,
  current,
}: {
  ariaLabel: string
  tabs: ReadonlyArray<DetailTab>
  params: { userId: string } | { roleId: string } | { groupId: string }
  current: DetailTab['to']
}) {
  const t = useTranslator()
  return (
    <nav
      aria-label={ariaLabel}
      className="mb-4 overflow-x-auto overflow-y-hidden border-b border-separator"
    >
      <ul className="flex min-w-max items-center gap-1">
        {tabs.map((tab) => {
          const Icon = tab.icon
          const active = tab.to === current
          return (
            <li key={tab.label}>
              <Link
                to={tab.to}
                params={params}
                activeOptions={{ exact: true }}
                aria-current={active ? 'page' : undefined}
                className={`-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus ${
                  active
                    ? 'border-accent font-semibold text-foreground'
                    : 'border-transparent text-muted hover:border-border hover:text-foreground'
                }`}
              >
                <Icon className="size-4" aria-hidden="true" />
                {t(tab.label)}
              </Link>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}

export function UserDetailTabs({
  userId,
  current,
}: {
  userId: string
  current:
    | '/users/$userId'
    | '/users/$userId/groups'
    | '/users/$userId/roles'
    | '/users/$userId/permissions'
}) {
  const t = useTranslator()

  // Additional tabs are introduced with their owning feature routes so the
  // detail shell never links to an unimplemented section.
  const tabs: DetailTab[] = [
    {
      label: 'userDetailsTabProfile',
      to: '/users/$userId',
      icon: UserRound,
    },
    {
      label: 'userDetailsTabGroups',
      to: '/users/$userId/groups',
      icon: UsersRound,
    },
    {
      label: 'userDetailsTabRoles',
      to: '/users/$userId/roles',
      icon: Shield,
    },
    {
      label: 'userDetailsTabPermissions',
      to: '/users/$userId/permissions',
      icon: KeyRound,
    },
  ]

  return (
    <DetailTabNav
      ariaLabel={t('userDetailTabsLabel')}
      params={{ userId }}
      current={current}
      tabs={tabs}
    />
  )
}

export function GroupDetailTabs({
  groupId,
  current,
}: {
  groupId: string
  current:
    | '/groups/$groupId'
    | '/groups/$groupId/members'
    | '/groups/$groupId/roles'
}) {
  const t = useTranslator()
  return (
    <DetailTabNav
      ariaLabel={t('groupDetailTabsLabel')}
      params={{ groupId }}
      current={current}
      tabs={[
        {
          label: 'groupTabOverview',
          to: '/groups/$groupId',
          icon: Info,
        },
        {
          label: 'groupTabMembers',
          to: '/groups/$groupId/members',
          icon: UsersRound,
        },
        {
          label: 'groupTabRoles',
          to: '/groups/$groupId/roles',
          icon: Shield,
        },
      ]}
    />
  )
}

export function RoleDetailTabs({
  roleId,
  current,
}: {
  roleId: string
  current:
    | '/roles/$roleId'
    | '/roles/$roleId/permissions'
    | '/roles/$roleId/users'
    | '/roles/$roleId/groups'
}) {
  const t = useTranslator()
  return (
    <DetailTabNav
      ariaLabel={t('roleDetailTabsLabel')}
      params={{ roleId }}
      current={current}
      tabs={[
        {
          label: 'roleTabSettings',
          to: '/roles/$roleId',
          icon: Shield,
        },
        {
          label: 'roleTabPermissions',
          to: '/roles/$roleId/permissions',
          icon: KeyRound,
        },
        {
          label: 'roleTabUsers',
          to: '/roles/$roleId/users',
          icon: UsersRound,
        },
        {
          label: 'roleTabGroups',
          to: '/roles/$roleId/groups',
          icon: UsersRound,
        },
      ]}
    />
  )
}
