import { createFileRoute } from '@tanstack/react-router'
import { ClientCredentialsPage } from '#/modules/client-management/clients/pages/client-credentials-page'
export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/credentials')({
  component: ClientCredentialsPage,
})
