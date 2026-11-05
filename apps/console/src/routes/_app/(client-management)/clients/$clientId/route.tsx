import { createFileRoute } from '@tanstack/react-router'
import { ClientDetailShell } from '#/modules/client-management/clients/components/client-detail-shell'
export const Route = createFileRoute('/_app/(client-management)/clients/$clientId')({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'clientsTitle', to: '/clients' },
      { label: 'clientsDetailTitle' },
    ],
  },
  component: () => <ClientDetailShell clientId={Route.useParams().clientId} />,
})
