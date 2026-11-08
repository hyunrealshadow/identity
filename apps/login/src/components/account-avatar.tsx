import { Avatar, AvatarFallback } from '@identity/ui/components/avatar'
import { cn } from '@identity/ui/lib/utils'

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
  const sizeClass = size === 'lg' ? 'size-12 text-base' : size === 'md' ? 'size-10 text-sm' : 'size-9 text-xs'

  return (
    <Avatar className={cn(sizeClass, className)}>
      <AvatarFallback className="bg-foreground font-semibold text-background">
        {accountInitials(name)}
      </AvatarFallback>
    </Avatar>
  )
}
