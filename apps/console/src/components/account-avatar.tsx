import { Avatar, AvatarFallback, AvatarImage } from '@identity/ui/components/avatar'

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
  size = 'sm',
  className,
}: {
  name: string
  picture?: string | null
  label: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}) {
  const fallbackSize =
    size === 'lg' ? 'text-base' : size === 'md' ? 'text-sm' : 'text-xs'
  const avatarSize = size === 'md' ? 'default' : size
  return (
    <Avatar size={avatarSize} className={className} aria-label={label}>
      {picture ? <AvatarImage src={picture} alt="" /> : null}
      <AvatarFallback
        className={`bg-foreground font-semibold text-background ${fallbackSize}`}
      >
        {initials(name)}
      </AvatarFallback>
    </Avatar>
  )
}
