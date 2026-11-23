import { createFileRoute } from '@tanstack/react-router'
import { EmailTemplatesPage } from '#/modules/instance/email/pages/email-templates-page'
export const Route = createFileRoute('/_app/(instance)/email/templates/')({
  staticData: {
    breadcrumbs: [{ label: 'emailTabTemplates' }],
  },
  component: EmailTemplatesPage,
})
