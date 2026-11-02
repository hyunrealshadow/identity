import { Skeleton } from '@heroui/react'
import { AsyncState } from '#/components/async-state'
import { CopyButton } from '#/components/copy-button'
import { useLocale, useTranslator } from '#/lib/i18n'
import { formatDateTime } from '#/lib/format'
import { useResourceContext } from '../components/resource-detail-shell'
export function ResourceDetailPage() {
  const { resource, canRead } = useResourceContext()
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  if (!canRead) return <AsyncState kind="forbidden" />
  if (!resource)
    return (
      <div
        className="grid gap-6 sm:grid-cols-2"
        aria-busy="true"
        aria-label={t('loading')}
      >
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-14 rounded-field" />
        ))}
      </div>
    )
  return (
    <dl className="grid gap-x-10 gap-y-7 py-3 sm:grid-cols-2">
      <div>
        <dt className="mb-2 text-sm text-muted">{t('resourcesName')}</dt>
        <dd className="text-sm">{resource.name}</dd>
      </div>
      <div>
        <dt className="mb-2 text-sm text-muted">{t('resourcesIdentifier')}</dt>
        <dd className="flex items-center gap-1">
          <code className="break-all text-sm">{resource.uri}</code>
          <CopyButton value={resource.uri} label={t('audienceLabel')} />
        </dd>
      </div>
      <div>
        <dt className="mb-2 text-sm text-muted">{t('rbacEntityCreated')}</dt>
        <dd className="text-sm">
          {formatDateTime(resource.createdAt, locale, timeZone)}
        </dd>
      </div>
      <div>
        <dt className="mb-2 text-sm text-muted">{t('rbacEntityUpdated')}</dt>
        <dd className="text-sm">
          {formatDateTime(resource.updatedAt, locale, timeZone)}
        </dd>
      </div>
    </dl>
  )
}
