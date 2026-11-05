import { createFileRoute } from '@tanstack/react-router'
import { ClientScopesPage } from '#/modules/client-management/clients/pages/client-scopes-page'
export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/scopes')({
  component: ClientScopesPage,
})
