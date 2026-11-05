import { createFileRoute } from '@tanstack/react-router'
import { ClientCreatePage } from '#/modules/client-management/clients/pages/client-create-page'
export const Route = createFileRoute('/_app/(client-management)/clients/new')({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'clientsTitle', to: '/clients' },
      { label: 'clientsNewTitle' },
    ],
  },
  component: ClientCreatePage,
})
