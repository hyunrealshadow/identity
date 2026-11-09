import { Avatar, AvatarFallback, AvatarImage } from '@identity/ui/components/avatar'
import type { ComponentProps } from 'react'

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  if (parts.length === 1) return Array.from(parts[0]).slice(0, 2).join('').toLocaleUpperCase()
  return `${Array.from(parts[0])[0]}${Array.from(parts[parts.length - 1])[0]}`.toLocaleUpperCase()
}

export function AccountAvatar({
  name,
  picture,
  label,
  size,
  className,
}: {
  name: string
  picture?: string | null
  label: string
  size?: ComponentProps<typeof Avatar>['size']
  className?: string
}) {
  return (
    <Avatar size={size} className={className} aria-label={label}>
      {picture ? <AvatarImage src={picture} alt="" /> : null}
      <AvatarFallback>{initials(name)}</AvatarFallback>
    </Avatar>
  )
}
