import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useTranslator } from '#/lib/i18n'

export function ErrorDetails({ issues }: { issues?: ReadonlyArray<GraphQLIssue> }) {
  const t = useTranslator()
  if (!issues?.length) return null

  return (
    <div className="mt-3">
      <p className="text-xs font-medium text-muted">{t('errorDetailsLabel')}</p>
      <ul className="mt-1.5 space-y-1 text-xs">
        {issues.map((issue, index) => {
          const code = issue.code !== undefined ? String(issue.code) : issue.kind
          return (
            <li key={`${code ?? 'error'}-${index}`} className="break-words">
              {issue.message ? <span>{issue.message}</span> : null}
              {code ? (
                <code className="ms-1.5 rounded bg-surface-secondary px-1 py-0.5 font-mono text-[10px] text-muted">
                  {code}
                </code>
              ) : null}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
