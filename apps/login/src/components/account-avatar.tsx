import { Avatar, AvatarFallback, AvatarImage } from '@identity/ui/components/avatar'
import type { ComponentProps } from 'react'

export function accountInitials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  if (parts.length === 1) return Array.from(parts[0]).slice(0, 2).join('').toLocaleUpperCase()
  return `${Array.from(parts[0])[0]}${Array.from(parts[parts.length - 1])[0]}`.toLocaleUpperCase()
}

export function AccountAvatar({
  name,
  picture,
  size,
  className,
}: {
  name: string
  picture?: string | null
  size?: ComponentProps<typeof Avatar>['size']
  className?: string
}) {
  return (
    <Avatar size={size} className={className}>
      {picture ? <AvatarImage src={picture} alt="" /> : null}
      <AvatarFallback>{accountInitials(name)}</AvatarFallback>
    </Avatar>
  )
}
