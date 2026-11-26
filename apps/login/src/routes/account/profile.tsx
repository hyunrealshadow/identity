import { createFileRoute } from '@tanstack/react-router'

import { ProfilePageView } from '#/modules/account/pages/profile-page'

export const Route = createFileRoute('/account/profile')({
  component: ProfilePageView,
})
