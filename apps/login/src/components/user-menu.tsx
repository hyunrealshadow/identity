import { Dropdown, Label } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { useServerFn } from '@tanstack/react-start'
import { ArrowLeftRight, LogOut } from 'lucide-react'
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
  signOutLabel: string
  switchAccountLabel: string
  requestFailedLabel: string
}

/**
 * Account menu for the SPA-only account area. Sign-out invokes the account server function
 * and follows the provider logout redirect returned by the server. Switch account
 * starts a normal sign-in with explicit provider-side account selection.
 */
export function UserMenu({
  user,
  menuLabel,
  signOutLabel,
  switchAccountLabel,
  requestFailedLabel,
}: UserMenuProps) {
  const router = useRouter()
  const execute = useServerFn(runAccountAction)
  const [isPending, setIsPending] = useState(false)
  const [requestError, setRequestError] = useState<string>()

  async function onAction(key: React.Key) {
    const action = key === 'signout' ? 'logout' : key === 'switch-account' ? 'switch-account' : undefined
    if (!action || isPending) return
    setIsPending(true)
    setRequestError(undefined)
    try {
      const result = await execute({
        data: { action, values: {} },
      })
      if (result.redirect) {
        window.location.assign(result.redirect)
        return
      }
      await router.invalidate()
    } catch {
      setRequestError(requestFailedLabel)
    } finally {
      setIsPending(false)
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
          <Dropdown.Item id="switch-account" textValue={switchAccountLabel}>
            <ArrowLeftRight className="size-4 shrink-0 text-muted" aria-hidden="true" />
            <Label>{switchAccountLabel}</Label>
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
