import { createFileRoute } from '@tanstack/react-router'

import { IdentifiersPageView } from '#/modules/account/pages/identifiers-page'

export const Route = createFileRoute('/account/identifiers')({
  component: IdentifiersPageView,
})
