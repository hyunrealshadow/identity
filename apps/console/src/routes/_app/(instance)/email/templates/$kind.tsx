import { createFileRoute } from '@tanstack/react-router'
import { EmailTemplatePage } from '#/modules/instance/email/pages/email-template-page'

function EmailTemplateRouteComponent() {
  const { kind } = Route.useParams()
  return <EmailTemplatePage slug={kind} />
}

export const Route = createFileRoute('/_app/(instance)/email/templates/$kind')({
  staticData: {
    breadcrumbs: [
      { label: 'emailTabTemplates', to: '/email/templates' },
      { label: 'settingsEmailTemplateCrumb' },
    ],
  },
  component: EmailTemplateRouteComponent,
})
