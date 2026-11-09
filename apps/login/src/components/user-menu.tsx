import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { useRouter } from '@tanstack/react-router'
import { useServerFn } from '@tanstack/react-start'
import { ArrowLeftRight, ChevronDown, LogOut } from 'lucide-react'
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
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            aria-label={menuLabel}
            className="h-10 max-w-64 gap-2 px-1.5"
          />
        }
      >
        <AccountAvatar name={user.name} picture={user.picture} />
        <span className="hidden min-w-0 text-start sm:block">
          <span className="block truncate text-sm font-medium">{user.name}</span>
          <span className="block truncate text-xs font-normal text-muted-foreground">{user.email}</span>
        </span>
        <ChevronDown className="hidden size-3.5 text-muted-foreground sm:block" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
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
