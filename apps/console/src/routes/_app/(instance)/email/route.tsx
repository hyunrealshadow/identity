import { createFileRoute } from '@tanstack/react-router'
import { EmailShell } from '#/modules/instance/email/components/email-shell'
export const Route = createFileRoute('/_app/(instance)/email')({
  staticData: {
    breadcrumbs: [
      { label: 'navInstance', link: false },
      { label: 'emailTitle', to: '/email' },
    ],
  },
  component: EmailShell,
})
