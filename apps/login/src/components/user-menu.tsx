import { Dropdown, Label } from '@heroui/react'
import { useNavigate, useRouter } from '@tanstack/react-router'
import { useServerFn } from '@tanstack/react-start'
import { LogOut, UserRound } from 'lucide-react'
import { useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { runAccountAction } from '#/lib/account-actions'

export interface AccountMenuUser {
  name: string
  email: string
  picture?: string
}

interface UserMenuProps {
  user: AccountMenuUser
  menuLabel: string
  manageLabel: string
  signOutLabel: string
  requestFailedLabel: string
}

/**
 * Clerk UserButton-style account menu. Rendered inside a `.js-only` gate; the
 * The account area is SPA-only; sign-out invokes the account server function
 * and follows the provider logout redirect returned by the server.
 */
export function UserMenu({ user, menuLabel, manageLabel, signOutLabel, requestFailedLabel }: UserMenuProps) {
  const navigate = useNavigate()
  const router = useRouter()
  const execute = useServerFn(runAccountAction)
  const [isSigningOut, setIsSigningOut] = useState(false)
  const [requestError, setRequestError] = useState<string>()

  async function onAction(key: React.Key) {
    if (key === 'manage') {
      void navigate({ to: '/account/profile' })
    } else if (key === 'signout') {
      if (isSigningOut) return
      setIsSigningOut(true)
      setRequestError(undefined)
      try {
        const result = await execute({
          data: { action: 'logout', values: {} },
        })
        if (result.redirect) {
          window.location.assign(result.redirect)
          return
        }
        await router.invalidate()
      } catch {
        setRequestError(requestFailedLabel)
      } finally {
        setIsSigningOut(false)
      }
    }
  }

  return (
    <Dropdown>
      <Dropdown.Trigger aria-label={menuLabel} className="cursor-pointer rounded-full">
        <AccountAvatar name={user.name} picture={user.picture} />
      </Dropdown.Trigger>
      <Dropdown.Popover className="min-w-[220px]" placement="bottom end">
        <div className="border-b border-separator px-3 pb-2.5 pt-3">
          <p className="truncate text-sm font-medium">{user.name}</p>
          <p className="truncate text-xs text-muted">{user.email}</p>
        </div>
        <Dropdown.Menu onAction={(key) => void onAction(key)}>
          <Dropdown.Item id="manage" textValue={manageLabel}>
            <UserRound className="size-4 shrink-0 text-muted" aria-hidden="true" />
            <Label>{manageLabel}</Label>
          </Dropdown.Item>
          <Dropdown.Item id="signout" textValue={signOutLabel} variant="danger">
            <LogOut className="size-4 shrink-0 text-danger" aria-hidden="true" />
            <Label>{signOutLabel}</Label>
          </Dropdown.Item>
        </Dropdown.Menu>
        {requestError ? <p className="px-3 pb-3 text-xs text-danger">{requestError}</p> : null}
      </Dropdown.Popover>
    </Dropdown>
  )
}
