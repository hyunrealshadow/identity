import { Avatar } from '@heroui/react'

interface AccountAvatarProps {
  name: string
  picture?: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

export function accountInitials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  if (parts.length === 1) return Array.from(parts[0]).slice(0, 2).join('').toLocaleUpperCase()
  return `${Array.from(parts[0])[0]}${Array.from(parts[parts.length - 1])[0]}`.toLocaleUpperCase()
}

export function AccountAvatar({ name, size = 'sm', className }: AccountAvatarProps) {
  const fallbackSize = size === 'lg' ? 'text-base' : size === 'md' ? 'text-sm' : 'text-xs'

  return (
    <Avatar size={size} className={className}>
      <Avatar.Fallback className={`bg-foreground font-semibold text-background ${fallbackSize}`}>
        {accountInitials(name)}
      </Avatar.Fallback>
    </Avatar>
  )
}
