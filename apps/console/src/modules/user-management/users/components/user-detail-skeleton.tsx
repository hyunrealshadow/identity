import { Button, Card, Skeleton } from '@heroui/react'
import type { ReactNode } from 'react'

import { UserSelectField } from './user-form-fields'

import { useTranslator } from '#/lib/i18n'

export function UserDetailPaginationSkeleton() {
  return (
    <div
      className="flex w-full flex-col items-start justify-between gap-4 sm:flex-row sm:items-center"
      aria-hidden="true"
    >
      <div className="flex h-5 items-center">
        <Skeleton className="h-4 w-24 rounded-field" />
      </div>
      <Skeleton className="h-9 w-40 rounded-field md:h-8" />
    </div>
  )
}

export function UserDetailTableSkeleton({ label }: { label: string }) {
  return (
    <div
      className="space-y-3 p-4"
      role="status"
      aria-label={label}
      aria-busy="true"
    >
      <div aria-hidden="true" className="space-y-3">
        <Skeleton className="h-9 w-full rounded-field" />
        {Array.from({ length: 4 }, (_, index) => (
          <div
            key={index}
            className="grid grid-cols-3 items-center gap-4 border-b border-separator py-3"
          >
            <div className="space-y-2">
              <Skeleton className="h-4 w-4/5 rounded-field" />
              <Skeleton className="h-3 w-3/5 rounded-field" />
            </div>
            <Skeleton className="h-4 w-2/3 rounded-field" />
            <Skeleton className="h-4 w-3/4 rounded-field" />
          </div>
        ))}
      </div>
    </div>
  )
}

export function UserDetailTabSkeleton({
  tab,
}: {
  userId?: string
  tab: 'groups' | 'roles' | 'permissions'
}) {
  const t = useTranslator()
  return (
    <section className="space-y-5" aria-busy="true">
      <div
        className="flex flex-wrap items-end justify-between gap-3"
        aria-hidden="true"
      >
        <div className="space-y-3">
          <Skeleton className="h-4 w-64 rounded-field" />
          {tab === 'permissions' ? (
            <div className="w-96 max-w-full">
              <UserSelectField
                name="pending-resource"
                label={t('rbacApiResource')}
                value=""
                onChange={() => undefined}
                options={[]}
                isDisabled
              />
            </div>
          ) : (
            <Skeleton className="h-10 w-48 rounded-field" />
          )}
        </div>
        {tab !== 'permissions' ? (
          <Skeleton className="h-10 w-32 rounded-field" />
        ) : null}
      </div>
      <UserDetailTableSkeleton label={t('loading')} />
      <UserDetailPaginationSkeleton />
    </section>
  )
}

export function UserDetailActionSkeleton({
  label,
  icon,
}: {
  label: string
  icon: ReactNode
}) {
  return (
    <div className="relative" aria-hidden="true">
      <Button isDisabled className="invisible">
        {icon}
        {label}
      </Button>
      <Skeleton className="absolute inset-0 rounded-field" />
    </div>
  )
}

export function UserDetailSkeleton() {
  const t = useTranslator()
  return (
    <div
      role="status"
      aria-label={t('usersDetailLoading')}
      aria-busy="true"
      className="space-y-5"
    >
      <Card
        className="console-card border border-border p-0"
        aria-hidden="true"
      >
        <Card.Content className="block p-5 sm:p-6">
          <div className="mb-6 flex h-6 items-center justify-between gap-3">
            <Skeleton className="h-5 w-20 rounded-field" />
          </div>
          <div className="grid gap-x-8 gap-y-7 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 4 }, (_, index) => (
              <div key={index} className="min-w-0">
                <Skeleton className="h-5 w-20 rounded-field" />
                <div className="mt-2 flex h-6 items-center">
                  <Skeleton className="h-5 w-40 max-w-full rounded-field" />
                </div>
              </div>
            ))}
          </div>
        </Card.Content>
      </Card>
      <Card
        className="console-card border border-border p-0"
        aria-hidden="true"
      >
        <Card.Content className="block p-5 sm:p-6">
          <div className="mb-6 flex h-6 items-center justify-between gap-3">
            <Skeleton className="h-5 w-20 rounded-field" />
          </div>
          <div className="py-4">
            <Skeleton className="h-5 w-36 rounded-field" />
          </div>
        </Card.Content>
      </Card>
    </div>
  )
}
