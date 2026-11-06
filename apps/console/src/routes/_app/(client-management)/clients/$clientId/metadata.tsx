import { createFileRoute } from '@tanstack/react-router'

import { ClientMetadataPage } from '#/modules/client-management/clients/pages/client-metadata-page'

export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/metadata')({
  component: ClientMetadataPage,
})
