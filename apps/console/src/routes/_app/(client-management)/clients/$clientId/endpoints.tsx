import { createFileRoute } from '@tanstack/react-router'

import { ClientEndpointsPage } from '#/modules/client-management/clients/pages/client-endpoints-page'

export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/endpoints')({
  component: ClientEndpointsPage,
})
