import { createFileRoute } from '@tanstack/react-router'

import { ClientIntegrationPage } from '#/modules/client-management/clients/pages/client-integration-page'

export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/integration')({
  component: ClientIntegrationPage,
})
