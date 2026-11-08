import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import { Card } from '@identity/ui/components/card'
import { createFileRoute } from '@tanstack/react-router'
import { Globe2, Laptop, Smartphone, Tablet } from 'lucide-react'

import { AccountActionForm } from '#/components/account-action-form'
import { PageHeading } from '#/components/account-settings'
import { translate } from '#/lib/i18n'
import {
  formatAccountExactDateTime,
  formatRecentActivity,
  useAccountTimeZone,
} from '#/lib/time-zone'
import { type AccountSession, useAccount } from './route'

export const Route = createFileRoute('/account/sessions')({ component: SessionsPage })

function SessionsPage() {
  const { locale, data } = useAccount()
  const timeZone = useAccountTimeZone(data.account.zoneInfo)
  const sessions = data.sessions.edges.map((edge) => edge.node)
  const current = sessions.find((session) => session.current)
  const others = sessions.filter((session) => !session.current)
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <>
      <PageHeading title={t('accountActiveDevices')} description={t('accountSessionsDescription')} />
      <div className="space-y-4">
        {current ? (
          <Card className="account-card gap-0 py-0">
            <div className="flex gap-3.5 px-5 py-4 sm:items-start sm:gap-4 sm:px-6">
              <div className="mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-xl bg-success/10 text-success">
                <DeviceIcon type={current.deviceType} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="truncate text-sm font-medium text-foreground" title={sessionTitle(current, t('accountUnknownDevice'))}>{sessionTitle(current, t('accountUnknownDevice'))}</p>
                  <Badge variant="outline" className="border-success/30 bg-success/10 text-success">{t('accountThisDevice')}</Badge>
                </div>
                {sessionDetails(current) ? <p className="mt-0.5 truncate text-sm text-muted-foreground" title={sessionDetails(current)}>{sessionDetails(current)}</p> : null}
                {current.ipAddress ? <p className="mt-1 text-xs text-muted-foreground"><span className="font-medium">IP</span> {current.ipAddress}</p> : null}
              </div>
              <time className="shrink-0 text-xs text-muted-foreground" dateTime={current.lastActiveAt ?? current.createdAt} title={`${formatAccountExactDateTime(current.lastActiveAt ?? current.createdAt, locale, timeZone)} (${timeZone})`}>{formatRecentActivity(current.lastActiveAt ?? current.createdAt, locale, timeZone)}</time>
            </div>
          </Card>
        ) : null}
        <Card className="account-card gap-0 py-0">
          <h2 className="border-b border-border px-5 py-4 text-sm font-semibold sm:px-6">{t('accountOtherDevices')}</h2>
          {others.length ? (
            <>
              <ul className="max-h-[min(32rem,60dvh)] divide-y divide-border overflow-y-auto overscroll-contain" tabIndex={0} aria-label={t('accountOtherDevices')}>
                {others.map((session) => {
                  const title = sessionTitle(session, t('accountUnknownDevice'))
                  const details = sessionDetails(session)
                  const activityAt = session.lastActiveAt ?? session.createdAt

                  return (
                    <li key={session.id} className="flex gap-3.5 px-5 py-4 sm:items-start sm:gap-4 sm:px-6">
                      <div className="mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-xl bg-muted text-muted-foreground">
                        <DeviceIcon type={session.deviceType} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-foreground" title={title}>{title}</p>
                        {details ? <p className="mt-0.5 truncate text-sm text-muted-foreground" title={details}>{details}</p> : null}
                        {session.ipAddress ? <p className="mt-1 text-xs text-muted-foreground"><span className="font-medium">IP</span> {session.ipAddress}</p> : null}
                      </div>
                      <div className="flex shrink-0 flex-col items-end gap-2">
                        <time className="text-xs text-muted-foreground" dateTime={activityAt} title={`${formatAccountExactDateTime(activityAt, locale, timeZone)} (${timeZone})`}>{formatRecentActivity(activityAt, locale, timeZone)}</time>
                        <AccountActionForm action="revoke-session" requestFailedMessage={t('accountRequestFailed')}>
                          <input type="hidden" name="session_id" value={session.id} />
                          <Button type="submit" size="sm" variant="destructive">{t('accountRevoke')}</Button>
                        </AccountActionForm>
                      </div>
                    </li>
                  )
                })}
              </ul>
              <div className="flex justify-end border-t border-border bg-muted/40 px-5 py-3 sm:px-6">
                <AccountActionForm action="revoke-others" requestFailedMessage={t('accountRequestFailed')}>
                  <Button type="submit" size="sm" variant="destructive">{t('accountRevokeOthers')}</Button>
                </AccountActionForm>
              </div>
            </>
          ) : (
            <p className="px-5 py-6 text-sm text-muted-foreground sm:px-6">{t('accountNoOtherDevices')}</p>
          )}
        </Card>
      </div>
    </>
  )
}

function DeviceIcon({ type }: { type?: string }) {
  const normalized = type?.toLowerCase()
  if (normalized?.includes('phone') || normalized === 'mobile') return <Smartphone className="size-5" aria-hidden="true" />
  if (normalized?.includes('tablet')) return <Tablet className="size-5" aria-hidden="true" />
  if (normalized === 'pc' || normalized?.includes('desktop')) return <Laptop className="size-5" aria-hidden="true" />
  return <Globe2 className="size-5" aria-hidden="true" />
}

function sessionTitle(session: AccountSession, fallback: string) {
  if (session.deviceName && session.browserName && session.deviceName !== session.browserName) return session.deviceName
  return [session.browserName ?? session.deviceName, session.browserVersion].filter(Boolean).join(' ') || fallback
}

function sessionDetails(session: AccountSession) {
  const browser = session.deviceName && session.browserName && session.deviceName !== session.browserName
    ? [session.browserName, session.browserVersion].filter(Boolean).join(' ')
    : undefined
  const operatingSystem = [session.osName, session.osVersion].filter(Boolean).join(' ')
  return [browser, operatingSystem].filter(Boolean).join(' ')
}
