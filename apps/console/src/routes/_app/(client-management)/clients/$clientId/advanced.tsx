import { createFileRoute } from '@tanstack/react-router'

import { ClientAdvancedPage } from '#/modules/client-management/clients/pages/client-advanced-page'

export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/advanced')({
  component: ClientAdvancedPage,
})
