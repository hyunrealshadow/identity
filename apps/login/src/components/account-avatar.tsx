import { Avatar } from '@heroui/react'

interface AccountAvatarProps {
  name: string
  picture?: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

export function accountInitial(name: string) {
  return Array.from(name.trim())[0]?.toLocaleUpperCase() ?? '?'
}

export function AccountAvatar({ name, picture, size = 'sm', className }: AccountAvatarProps) {
  const fallbackSize = size === 'lg' ? 'text-base' : size === 'md' ? 'text-sm' : 'text-xs'

  return (
    <Avatar size={size} className={className}>
      {picture ? <Avatar.Image alt="" src={picture} /> : null}
      <Avatar.Fallback className={`bg-foreground font-semibold text-background ${fallbackSize}`}>
        {accountInitial(name)}
      </Avatar.Fallback>
    </Avatar>
  )
}
