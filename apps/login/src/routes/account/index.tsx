import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/account/')({
  loader: () => {
    throw redirect({ to: '/account/profile' })
  },
})
