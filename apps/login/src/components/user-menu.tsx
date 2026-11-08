import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
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

  async function onAction(key: 'signout' | 'switch-account') {
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
    <DropdownMenu>
      <DropdownMenuTrigger aria-label={menuLabel} className="cursor-pointer rounded-full outline-none focus-visible:ring-3 focus-visible:ring-ring/50">
        <AccountAvatar name={user.name} picture={user.picture} />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[220px]">
        <div className="px-2 pb-2 pt-1.5">
          <p className="truncate text-sm font-medium">{user.name}</p>
          <p className="truncate text-xs text-muted-foreground">{user.email}</p>
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem onClick={() => void onAction('switch-account')}>
            <ArrowLeftRight className="text-muted-foreground" aria-hidden="true" />
            {switchAccountLabel}
          </DropdownMenuItem>
          <DropdownMenuItem variant="destructive" onClick={() => void onAction('signout')}>
            <LogOut aria-hidden="true" />
            {signOutLabel}
          </DropdownMenuItem>
        </DropdownMenuGroup>
        {requestError ? <p role="alert" className="px-2 pb-2 pt-1 text-xs text-destructive">{requestError}</p> : null}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
