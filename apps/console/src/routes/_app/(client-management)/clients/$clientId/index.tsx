import { createFileRoute } from '@tanstack/react-router'

import { ClientGeneralPage } from '#/modules/client-management/clients/pages/client-general-page'

export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/')({
  component: ClientGeneralPage,
})
