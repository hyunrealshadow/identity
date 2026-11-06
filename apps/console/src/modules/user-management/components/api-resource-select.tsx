import { Button, ComboBox, Input, Label, ListBox } from '@heroui/react'
import { useEffect, useMemo, useState } from 'react'

import {
  ConsoleResourceOptionsDocument,
  type ConsoleResourceOptionsQuery,
  type ConsoleResourceOptionsQueryVariables,
} from '#/generated/graphql'
import { useTranslator } from '#/lib/i18n'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

type Resource =
  ConsoleResourceOptionsQuery['resources']['edges'][number]['node']

export function ApiResourceSelect({
  value,
  onChange,
  enabled = true,
}: {
  value: string
  onChange: (id: string) => void
  enabled?: boolean
}) {
  const t = useTranslator()
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [after, setAfter] = useState<string>()
  const [items, setItems] = useState<Resource[]>([])
  const [selected, setSelected] = useState<Resource>()
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = text === selected?.name ? '' : text.trim()
      if (query !== next) {
        setQuery(next)
        setAfter(undefined)
        setItems([])
      }
    }, 250)
    return () => window.clearTimeout(timer)
  }, [text, selected?.name, query])
  const variables = useMemo(
    () =>
      enabled ? { first: 20, after, filter: query ? { query } : {} } : null,
    [enabled, after, query],
  )
  const resources = useConsoleQuery<
    ConsoleResourceOptionsQuery,
    ConsoleResourceOptionsQueryVariables
  >(
    ConsoleResourceOptionsDocument,
    variables,
    enabled,
    'missing_resource_connection',
  )
  useEffect(() => {
    if (!resources.data) return
    const next = resources.data.resources.edges.map((edge) => edge.node)
    setItems((current) =>
      after
        ? [
            ...new Map(
              [...current, ...next].map((node) => [node.id, node]),
            ).values(),
          ]
        : next,
    )
    if (!value && next[0]) {
      setSelected(next[0])
      setText(next[0].name)
      onChange(next[0].id)
    }
  }, [resources.data, after, value, onChange])
  const options =
    selected && !items.some((node) => node.id === selected.id)
      ? [selected, ...items]
      : items
  return (
    <ComboBox
      selectedKey={value || null}
      inputValue={text}
      onInputChange={setText}
      allowsEmptyCollection
      isDisabled={!enabled}
      className="w-full max-w-xl"
      onSelectionChange={(key) => {
        const node = options.find((item) => item.id === key)
        if (!node) return
        setSelected(node)
        setText(node.name)
        onChange(node.id)
      }}
    >
      <Label>{t('rbacApiResource')}</Label>
      <ComboBox.InputGroup>
        <Input placeholder={t('rbacSearchApi')} />
        <ComboBox.Trigger />
      </ComboBox.InputGroup>
      <ComboBox.Popover className="max-w-[calc(100vw-2rem)]">
        <ListBox
          items={options}
          renderEmptyState={() =>
            resources.status === 'loading' ? t('loading') : t('rbacNoResources')
          }
        >
          {(node) => (
            <ListBox.Item id={node.id} textValue={node.name}>
              <div className="min-w-0">
                <p className="truncate font-medium">{node.name}</p>
                <p className="truncate text-xs text-muted">{node.uri}</p>
              </div>
              <ListBox.ItemIndicator />
            </ListBox.Item>
          )}
        </ListBox>
        {resources.data?.resources.pageInfo.hasNextPage ? (
          <Button
            size="sm"
            variant="ghost"
            isDisabled={resources.status === 'loading'}
            onPress={() =>
              setAfter(
                resources.data?.resources.pageInfo.endCursor ?? undefined,
              )
            }
          >
            {t('rbacLoadMore')}
          </Button>
        ) : null}
        {resources.status === 'error' ? (
          <Button
            size="sm"
            variant="ghost"
            onPress={() => void resources.refresh()}
          >
            {t('retry')}
          </Button>
        ) : null}
      </ComboBox.Popover>
    </ComboBox>
  )
}
