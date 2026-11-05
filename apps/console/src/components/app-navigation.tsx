import { Button, Drawer, useOverlayState } from '@heroui/react'
import { Link } from '@tanstack/react-router'
import {
  AppWindow,
  Boxes,
  ChevronsLeft,
  ChevronsRight,
  LayoutDashboard,
  Menu,
  Shield,
  Users,
  UsersRound,
  type LucideIcon,
} from 'lucide-react'

import { useTranslator, type MessageKey } from '#/lib/i18n'

interface NavEntry {
  label: MessageKey
  to?: '/' | '/users' | '/groups' | '/roles' | '/clients' | '/resources'
  icon: LucideIcon
}

interface NavGroup {
  label: MessageKey
  entries: NavEntry[]
}

const overviewEntry: NavEntry = {
  label: 'navOverview',
  to: '/',
  icon: LayoutDashboard,
}

const groups: NavGroup[] = [
  {
    label: 'navClientManagement',
    entries: [
      { label: 'navClients', to: '/clients', icon: AppWindow },
      { label: 'navResources', to: '/resources', icon: Boxes },
    ],
  },
  {
    label: 'navUserManagement',
    entries: [
      { label: 'navUsers', to: '/users', icon: Users },
      { label: 'navGroups', to: '/groups', icon: UsersRound },
      { label: 'navRoles', to: '/roles', icon: Shield },
    ],
  },
]

function brandInitials(value: string): string {
  const words = value.trim().split(/\s+/u).filter(Boolean)
  const [first, second] = words
  if (!first) return ''
  const firstCharacters = Array.from(first)
  if (!second) return firstCharacters.slice(0, 2).join('').toLocaleUpperCase()
  return `${firstCharacters[0] ?? ''}${Array.from(second)[0] ?? ''}`.toLocaleUpperCase()
}

export function Brand({
  displayName,
  collapsed = false,
}: {
  displayName: string
  collapsed?: boolean
}) {
  const t = useTranslator()
  const consoleLabel = t('consoleLabel')
  const accessibleName = displayName.trim() || consoleLabel
  const initials = brandInitials(accessibleName)
  return (
    <div
      className={`flex min-w-0 items-center gap-2.5 ${collapsed ? 'justify-center' : ''}`}
    >
      {collapsed ? (
        <span
          className="flex size-9 shrink-0 items-center justify-center rounded-field bg-surface-secondary text-xs font-semibold tracking-tight text-foreground"
          title={accessibleName}
        >
          <span aria-hidden="true">{initials}</span>
          <span className="sr-only">{accessibleName}</span>
        </span>
      ) : (
        <span className="min-w-0">
          <span className="block truncate text-sm font-semibold tracking-tight text-foreground">
            {displayName}
          </span>
          <span className="block truncate text-[11px] font-medium uppercase tracking-wide text-muted">
            {consoleLabel}
          </span>
        </span>
      )}
    </div>
  )
}

export function NavigationLinks({
  collapsed,
  onNavigate,
}: {
  collapsed: boolean
  onNavigate?: () => void
}) {
  const t = useTranslator()

  const renderEntry = (entry: NavEntry) => {
    const Icon = entry.icon
    const label = t(entry.label)
    if (!entry.to) {
      return (
        <li key={entry.label}>
          <span
            role="link"
            aria-disabled="true"
            aria-label={`${label}. ${t('plannedLater')}`}
            title={t('plannedLater')}
            tabIndex={-1}
            className={`console-nav-link flex cursor-not-allowed items-center gap-2.5 rounded-field px-2.5 py-2 text-sm text-muted opacity-50 ${collapsed ? 'justify-center' : ''}`}
          >
            <Icon className="size-4 shrink-0" aria-hidden="true" />
            <span className={collapsed ? 'sr-only' : 'min-w-0 truncate'}>
              {label}
            </span>
            <span className="sr-only">{t('plannedLater')}</span>
          </span>
        </li>
      )
    }

    const base =
      'console-nav-link flex items-center gap-2.5 rounded-field px-2.5 py-2 text-sm text-muted'
    return (
      <li key={entry.label}>
        <Link
          to={entry.to}
          aria-label={label}
          title={collapsed ? label : undefined}
          onClick={onNavigate}
          className={`${base} ${collapsed ? 'justify-center' : ''}`}
          activeOptions={{ exact: entry.to === '/' }}
          activeProps={{
            className: `${base} console-nav-link-active font-medium ${collapsed ? 'justify-center' : ''}`,
          }}
        >
          <Icon className="size-4 shrink-0" aria-hidden="true" />
          <span className={collapsed ? 'sr-only' : 'min-w-0 truncate'}>
            {label}
          </span>
        </Link>
      </li>
    )
  }

  return (
    <div className="space-y-5">
      <ul className="space-y-0.5">{renderEntry(overviewEntry)}</ul>
      {groups.map((group) => (
        <nav key={group.label} aria-label={t(group.label)}>
          <p
            className={
              collapsed
                ? 'sr-only'
                : 'mb-1.5 px-2 text-[11px] font-semibold uppercase tracking-wider text-muted'
            }
          >
            {t(group.label)}
          </p>
          <ul className="space-y-0.5">
            {group.entries.map((entry) => renderEntry(entry))}
          </ul>
        </nav>
      ))}
    </div>
  )
}

export function SidebarCollapseButton({
  collapsed,
  onToggle,
}: {
  collapsed: boolean
  onToggle: () => void
}) {
  const t = useTranslator()
  const label = collapsed ? t('expandNavigation') : t('collapseNavigation')
  const Icon = collapsed ? ChevronsRight : ChevronsLeft

  return (
    <Button
      isIconOnly
      variant="ghost"
      size="sm"
      aria-label={label}
      aria-expanded={!collapsed}
      aria-controls="console-sidebar"
      onPress={onToggle}
    >
      <Icon className="size-4" aria-hidden="true" />
    </Button>
  )
}

export function MobileNavigation({ displayName }: { displayName: string }) {
  const t = useTranslator()
  const state = useOverlayState()

  return (
    <Drawer state={state}>
      <Drawer.Trigger
        aria-label={t('openNavigation')}
        className="inline-flex size-9 items-center justify-center rounded-field text-muted hover:bg-surface-secondary hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus lg:hidden"
      >
        <Menu className="size-5" aria-hidden="true" />
        <span className="sr-only">{t('openNavigation')}</span>
      </Drawer.Trigger>
      <Drawer.Backdrop>
        <Drawer.Content placement="left" className="w-[min(84vw,320px)]">
          <Drawer.Dialog>
            {({ close }) => (
              <>
                <Drawer.Header className="flex items-center justify-between gap-3 border-b border-separator px-4 py-3">
                  <Drawer.Heading className="sr-only">
                    {t('navigationLabel')}
                  </Drawer.Heading>
                  <Brand displayName={displayName} />
                  <Drawer.CloseTrigger aria-label={t('closeNavigation')} />
                </Drawer.Header>
                <Drawer.Body className="p-3">
                  <NavigationLinks collapsed={false} onNavigate={close} />
                </Drawer.Body>
              </>
            )}
          </Drawer.Dialog>
        </Drawer.Content>
      </Drawer.Backdrop>
    </Drawer>
  )
}
