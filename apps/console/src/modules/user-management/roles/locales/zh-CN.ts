import type enUS from './en-US'

const zhCN = {
  roleTabGroups: '用户组',
  roleGroupsTitle: '角色用户组',
  roleGroupsDescription: '当前通过有效关联授予此角色的用户组',
  roleGroupsListTitle: '关联用户组',
  roleGroupsListDescription:
    '与此角色有效关联的已启用用户组，角色关联请在用户组页面管理',
  roleGroupsFiltersLabel: '用户组筛选',
  roleGroupsSearchLabel: '搜索',
  roleGroupsSearchPlaceholder: '用户组名称或说明',
  roleGroupsKindLabel: '用户组类型',
  roleGroupsKindAny: '全部类型',
  roleGroupsKindBuiltIn: '仅内置',
  roleGroupsKindCustom: '仅自定义',
  roleGroupsOrderLabel: '排序',
  roleGroupsOrderCreatedDesc: '最新创建',
  roleGroupsOrderCreatedAsc: '最早创建',
  roleGroupsApplyFilters: '应用筛选',
  roleGroupsResetFilters: '重置筛选',
  roleGroupsActiveOnlyNote: '仅显示与此角色有效关联的已启用用户组',
  roleGroupsTableLabel: '此角色的关联用户组',
  roleGroupsColumnGroup: '用户组',
  roleGroupsColumnKind: '类型',
  roleGroupsColumnStatus: '状态',
  roleGroupsColumnUpdated: '更新时间',
  roleGroupsColumnActions: '操作',
  roleGroupsViewAction: '查看',
  roleGroupsViewFor: '查看 {name}',
  roleGroupsPreviousPage: '上一页',
  roleGroupsNextPage: '下一页',
  roleGroupsPaginationLabel: '关联用户组分页',
  roleGroupsPageSummary: '{count, plural, other {本页 # 个用户组}}',
  roleGroupsLoading: '正在加载关联用户组…',
  roleGroupsNotFoundTitle: '未找到角色',
  roleGroupsNotFoundDescription: '此角色可能已删除或无法读取',
  roleGroupsEmptyTitle: '此角色没有关联用户组',
  roleGroupsEmptyDescription:
    '当前没有已启用用户组通过有效关联授予此角色',
  roleGroupsNoResultsTitle: '没有符合筛选条件的用户组',
  roleGroupsNoResultsDescription:
    '请调整或重置筛选后查看其他关联用户组',
  roleGroupsClearFilters: '清除筛选',
  roleGroupsPartialTitle: '部分关联用户组数据无法加载',
  roleGroupsPartialDescription: '列表仍可使用，但服务器返回了错误',
  roleGroupsStepUpDescription:
    '完成两步验证后即可查看此角色的关联用户组',
  roleGroupsStepUpNote:
    '验证后请返回此页重试',
} satisfies Record<keyof typeof enUS, string>

export default zhCN
