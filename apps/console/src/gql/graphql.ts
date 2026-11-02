/* eslint-disable */
/** Internal type. DO NOT USE DIRECTLY. */
type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
/** Internal type. DO NOT USE DIRECTLY. */
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
import type { DocumentTypeDecoration } from '@graphql-typed-document-node/core';
export type AddGroupMemberInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  userId: string | number;
};

export type AssignUserRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedUserVersion: string;
  reason?: string;
  roleIds: Array<string | number>;
  userId: string | number;
};

export type CreateGroupInput = {
  clientMutationId?: string | null | undefined;
  description?: string;
  descriptions?: Array<LocalizedTextInput>;
  name: string;
  names?: Array<LocalizedTextInput>;
  reason?: string;
};

export type CreateRoleInput = {
  clientMutationId?: string | null | undefined;
  description?: string;
  descriptions?: Array<LocalizedTextInput>;
  name: string;
  names?: Array<LocalizedTextInput>;
  reason?: string;
};

export type CreateScopeInput = {
  clientMutationId?: string | null | undefined;
  code: string;
  description?: string;
  descriptions?: Array<ScopeDescriptionInput> | null | undefined;
  name: string;
  names?: Array<ScopeDescriptionInput>;
  reason?: string;
  /** Every custom scope is owned by an API resource. */
  resourceId: string | number;
};

export type CreateUserInput = {
  clientMutationId?: string | null | undefined;
  email: string;
  password: string;
  profile?: UserProfilePatchInput | null | undefined;
  reason?: string;
  username: string;
};

export type EffectivePermissionOrder =
  | 'CODE_ASC'
  | 'CODE_DESC';

export type GroupFilter = {
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
  roleId?: string | number | null | undefined;
  userId?: string | number | null | undefined;
};

export type GroupMembershipFilter = {
  enabled?: boolean | null | undefined;
  userId?: string | number | null | undefined;
};

export type GroupMembershipOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type GroupOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type GroupRoleFilter = {
  enabled?: boolean | null | undefined;
  roleId?: string | number | null | undefined;
};

export type GroupRoleOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'ROLE_NAME_ASC'
  | 'ROLE_NAME_DESC';

export type GroupStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type LocalizedTextInput = {
  locale: string;
  value: string;
};

export type RemoveGroupMemberInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  userId: string | number;
};

export type ResourceFilter = {
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
};

export type ResourceOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'NAME_ASC'
  | 'NAME_DESC'
  | 'URI_ASC'
  | 'URI_DESC';

export type RevokeUserRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedUserVersion: string;
  reason?: string;
  roleIds: Array<string | number>;
  userId: string | number;
};

export type RoleFilter = {
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
  /** Optional membership filter on a canonical scope identity. */
  scopeId?: string | number | null | undefined;
};

export type RoleOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'NAME_ASC'
  | 'NAME_DESC';

export type RoleStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type ScopeDescriptionInput = {
  locale: string;
  value: string;
};

export type ScopeFilter = {
  apiOnly?: boolean;
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
  resourceId?: string | number | null | undefined;
  roleId?: string | number | null | undefined;
};

export type ScopeOrder =
  | 'CODE_ASC'
  | 'CODE_DESC'
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type ScopeStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type SetGroupEnabledInput = {
  clientMutationId?: string | null | undefined;
  enabled: boolean;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type SetGroupRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  roleIds: Array<string | number>;
};

export type SetRolePermissionsInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  permissionIds: Array<string | number>;
  reason?: string;
  roleId: string | number;
};

export type UnlockUserInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type UpdateGroupInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<LocalizedTextInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<LocalizedTextInput> | null | undefined;
  reason?: string;
};

export type UpdateRoleInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<LocalizedTextInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<LocalizedTextInput> | null | undefined;
  reason?: string;
};

export type UpdateScopeInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<ScopeDescriptionInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<ScopeDescriptionInput> | null | undefined;
  reason?: string;
};

export type UpdateUserInput = {
  clientMutationId?: string | null | undefined;
  email?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  profile?: UserProfilePatchInput | null | undefined;
  reason?: string;
  username?: string | null | undefined;
};

export type UserFilter = {
  createdBefore?: string | null | undefined;
  createdFrom?: string | null | undefined;
  email?: string | null | undefined;
  enabled?: boolean | null | undefined;
  locked?: boolean | null | undefined;
  query?: string | null | undefined;
  username?: string | null | undefined;
};

/**
 * Stable user-management ordering. Explicit SDL names keep consumers and the
 * persisted cursor contract independent from Rust identifier conventions.
 */
export type UserOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'USERNAME_ASC'
  | 'USERNAME_DESC';

export type UserProfilePatchInput = {
  addressCountry?: string | null | undefined;
  addressFormatted?: string | null | undefined;
  addressLocality?: string | null | undefined;
  addressPostalCode?: string | null | undefined;
  addressRegion?: string | null | undefined;
  addressStreetAddress?: string | null | undefined;
  birthdate?: string | null | undefined;
  familyName?: string | null | undefined;
  gender?: string | null | undefined;
  givenName?: string | null | undefined;
  locale?: string | null | undefined;
  middleName?: string | null | undefined;
  nickname?: string | null | undefined;
  picture?: string | null | undefined;
  profile?: string | null | undefined;
  theme?: string | null | undefined;
  website?: string | null | undefined;
  zoneInfo?: string | null | undefined;
};

export type UserRoleBindingOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type UserStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type ConsoleBootstrapQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleBootstrapQuery = { effectivePermissions: { role: string | null, requestableScopes: Array<string>, grantedScopes: Array<string>, effectiveScopes: Array<string>, authentication: { acr: string | null, authTime: string | null, aal2: boolean, recent: boolean } }, instanceInfo: { name: string, environment: string, issuer: string, version: string } };

export type ConsoleResourcesQueryVariables = Exact<{
  filter?: ResourceFilter | null | undefined;
  orderBy?: ResourceOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleResourcesQuery = { resources: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, name: string, uri: string, enabled: boolean, createdAt: string, updatedAt: string | null } }> } };

export type ConsoleResourceQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleResourceQuery = { resource: { id: string, name: string, uri: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null } | null };

export type ConsolePermissionRolesQueryVariables = Exact<{
  id: string | number;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsolePermissionRolesQuery = { permission: { id: string, roles: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ node: { id: string, name: string, builtIn: boolean, enabled: boolean, description: string, names: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsolePermissionQueryVariables = Exact<{
  id: string | number;
  includeResource: boolean;
}>;


export type ConsolePermissionQuery = { permission: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, resource?: { id: string, uri: string, name: string, enabled: boolean } | null } | null };

export type ConsoleCreatePermissionMutationVariables = Exact<{
  input: CreateScopeInput;
}>;


export type ConsoleCreatePermissionMutation = { createPermission: { version: string, permissionId: string } };

export type ConsoleUpdatePermissionMutationVariables = Exact<{
  input: UpdateScopeInput;
}>;


export type ConsoleUpdatePermissionMutation = { updatePermission: { version: string, permissionId: string } };

export type ConsoleEnablePermissionMutationVariables = Exact<{
  input: ScopeStateInput;
}>;


export type ConsoleEnablePermissionMutation = { enablePermission: { version: string, permissionId: string } };

export type ConsoleDisablePermissionMutationVariables = Exact<{
  input: ScopeStateInput;
}>;


export type ConsoleDisablePermissionMutation = { disablePermission: { version: string, permissionId: string } };

export type ConsoleScopesQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleScopesQuery = { scopes: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, code: string, name: string, description: string, names: Array<{ locale: string, value: string }> } }> } };

export type ConsolePermissionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeResource: boolean;
}>;


export type ConsolePermissionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, resource?: { id: string, uri: string, name: string, enabled: boolean } | null } }> } };

export type ConsoleResourcePermissionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleResourcePermissionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, createdAt: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type InstanceDashboardQueryVariables = Exact<{
  timeZone: string;
  includeUsers: boolean;
  includeApplications: boolean;
  includeSessions: boolean;
  includeResources: boolean;
}>;


export type InstanceDashboardQuery = { instanceOverview: { generatedAt: string, users?: { total: number, enabled: number, createdLast7Days: number, registrations: Array<{ date: string, count: number }> } | null, applications?: { total: number, enabled: number, builtIn: number } | null, sessions?: { active: number, createdLast24Hours: number } | null, resources?: { total: number, enabled: number } | null } };

export type ConsoleUserRolesQueryVariables = Exact<{
  userId: string | number;
  enabled?: boolean | null | undefined;
  orderBy?: UserRoleBindingOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeRole: boolean;
}>;


export type ConsoleUserRolesQuery = { userRoles: { userVersion: string | null, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, userId: string, roleId: string, grantedByUserId: string | null, reason: string, enabled: boolean, revokedAt: string | null, version: string, userVersion: string, createdAt: string, updatedAt: string | null, role?: { id: string, name: string, description: string, enabled: boolean, names: Array<{ locale: string, value: string }> } | null } }> } };

export type ConsoleUserRoleVersionQueryVariables = Exact<{
  userId: string | number;
}>;


export type ConsoleUserRoleVersionQuery = { userRoles: { userVersion: string | null } };

export type ConsoleUserPermissionsQueryVariables = Exact<{
  userId: string | number;
  resourceId: string | number;
  orderBy?: EffectivePermissionOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserPermissionsQuery = { userPermissions: { totalCount: number, userVersion: string, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { permissionId: string, resourceId: string, code: string, sources: Array<{ bindingId: string, roleId: string }>, groupSources: Array<{ groupId: string, membershipId: string, groupRoleBindingId: string, roleId: string }> } }> } };

export type ConsoleAssignUserRolesMutationVariables = Exact<{
  input: AssignUserRolesInput;
}>;


export type ConsoleAssignUserRolesMutation = { assignUserRoles: { userId: string, userVersion: string, bindingIds: Array<string>, createdCount: number, revokedCount: number } };

export type ConsoleRevokeUserRolesMutationVariables = Exact<{
  input: RevokeUserRolesInput;
}>;


export type ConsoleRevokeUserRolesMutation = { revokeUserRoles: { userId: string, userVersion: string, bindingIds: Array<string>, createdCount: number, revokedCount: number } };

export type ConsoleAuthorizationLabelsQueryVariables = Exact<{
  ids: Array<string | number> | string | number;
}>;


export type ConsoleAuthorizationLabelsQuery = { nodes: Array<
    | { __typename: 'Group', name: string, id: string, names: Array<{ locale: string, value: string }> }
    | { __typename: 'GroupMembership', id: string }
    | { __typename: 'GroupRoleBinding', id: string }
    | { __typename: 'Resource', id: string }
    | { __typename: 'Role', name: string, description: string, id: string, names: Array<{ locale: string, value: string }> }
    | { __typename: 'Scope', code: string, name: string, description: string, id: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> }
    | { __typename: 'Session', id: string }
    | { __typename: 'User', id: string }
  > };

export type ConsoleGroupsQueryVariables = Exact<{
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleGroupsQuery = { groups: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleGroupQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleGroupQuery = { group: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } | null };

export type ConsoleGroupMembersQueryVariables = Exact<{
  groupId: string | number;
  filter?: GroupMembershipFilter | null | undefined;
  orderBy?: GroupMembershipOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeUser: boolean;
}>;


export type ConsoleGroupMembersQuery = { group: { id: string, builtIn: boolean, name: string, description: string, version: string, names: Array<{ locale: string, value: string }>, members: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, groupId: string, userId: string, grantedByUserId: string | null, enabled: boolean, revokedAt: string | null, version: string, createdAt: string, updatedAt: string | null, user?: { id: string, username: string, email: string, enabled: boolean | null, locked: boolean | null } | null } }> } } | null };

export type ConsoleGroupRolesQueryVariables = Exact<{
  groupId: string | number;
  filter?: GroupRoleFilter | null | undefined;
  orderBy?: GroupRoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeRole: boolean;
}>;


export type ConsoleGroupRolesQuery = { group: { id: string, builtIn: boolean, name: string, description: string, version: string, names: Array<{ locale: string, value: string }>, roles: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, groupId: string, roleId: string, grantedByUserId: string | null, enabled: boolean, revokedAt: string | null, version: string, createdAt: string, updatedAt: string | null, role?: { id: string, name: string, builtIn: boolean, description: string, enabled: boolean, version: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } | null } }> } } | null };

export type ConsoleGroupRoleIdsQueryVariables = Exact<{
  groupId: string | number;
  first: number;
  after?: string | null | undefined;
}>;


export type ConsoleGroupRoleIdsQuery = { group: { id: string, version: string, roles: { pageInfo: { hasNextPage: boolean, endCursor: string | null }, edges: Array<{ node: { roleId: string, enabled: boolean, revokedAt: string | null } }> } } | null };

export type ConsoleCreateGroupMutationVariables = Exact<{
  input: CreateGroupInput;
}>;


export type ConsoleCreateGroupMutation = { createGroup: { groupId: string, version: string } };

export type ConsoleUpdateGroupMutationVariables = Exact<{
  input: UpdateGroupInput;
}>;


export type ConsoleUpdateGroupMutation = { updateGroup: { groupId: string, version: string } };

export type ConsoleAddGroupMemberMutationVariables = Exact<{
  input: AddGroupMemberInput;
}>;


export type ConsoleAddGroupMemberMutation = { addGroupMember: { groupId: string, userId: string, membershipId: string, groupVersion: string, membershipVersion: string } };

export type ConsoleRemoveGroupMemberMutationVariables = Exact<{
  input: RemoveGroupMemberInput;
}>;


export type ConsoleRemoveGroupMemberMutation = { removeGroupMember: { groupId: string, userId: string, membershipId: string, groupVersion: string, membershipVersion: string } };

export type ConsoleSetGroupRolesMutationVariables = Exact<{
  input: SetGroupRolesInput;
}>;


export type ConsoleSetGroupRolesMutation = { setGroupRoles: { groupId: string, groupVersion: string, roleIds: Array<string>, addedCount: number, removedCount: number } };

export type ConsoleSetGroupEnabledMutationVariables = Exact<{
  input: SetGroupEnabledInput;
}>;


export type ConsoleSetGroupEnabledMutation = { setGroupEnabled: { groupId: string, version: string } };

export type ConsoleDeleteGroupMutationVariables = Exact<{
  input: GroupStateInput;
}>;


export type ConsoleDeleteGroupMutation = { deleteGroup: { groupId: string, deleted: boolean } };

export type ConsolePermissionOptionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsolePermissionOptionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleRoleGroupsQueryVariables = Exact<{
  roleId: string | number;
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleRoleGroupsQuery = { role: { id: string, groups: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleRolesQueryVariables = Exact<{
  filter?: RoleFilter | null | undefined;
  orderBy?: RoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleRolesQuery = { roles: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleRoleQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleRoleQuery = { role: { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } | null };

export type ConsoleCreateRoleMutationVariables = Exact<{
  input: CreateRoleInput;
}>;


export type ConsoleCreateRoleMutation = { createRole: { roleId: string, version: string } };

export type ConsoleUpdateRoleMutationVariables = Exact<{
  input: UpdateRoleInput;
}>;


export type ConsoleUpdateRoleMutation = { updateRole: { roleId: string, version: string } };

export type ConsoleEnableRoleMutationVariables = Exact<{
  input: RoleStateInput;
}>;


export type ConsoleEnableRoleMutation = { enableRole: { roleId: string, version: string } };

export type ConsoleDisableRoleMutationVariables = Exact<{
  input: RoleStateInput;
}>;


export type ConsoleDisableRoleMutation = { disableRole: { roleId: string, version: string } };

export type ConsoleSetRolePermissionsMutationVariables = Exact<{
  input: SetRolePermissionsInput;
}>;


export type ConsoleSetRolePermissionsMutation = { setRolePermissions: { roleId: string, version: string } };

export type ConsoleRoleUsersQueryVariables = Exact<{
  roleId: string | number;
  enabled?: boolean | null | undefined;
  orderBy?: UserRoleBindingOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeUser: boolean;
}>;


export type ConsoleRoleUsersQuery = { roleUsers: { userVersion: string | null, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, userId: string, roleId: string, grantedByUserId: string | null, reason: string, enabled: boolean, revokedAt: string | null, version: string, userVersion: string, createdAt: string, updatedAt: string | null, user?: { id: string, username: string, email: string, enabled: boolean | null, locked: boolean | null } | null } }> } };

export type ConsoleResourceOptionsQueryVariables = Exact<{
  filter?: ResourceFilter | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
}>;


export type ConsoleResourceOptionsQuery = { resources: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, uri: string, name: string, enabled: boolean } }> } };

export type ConsoleUsersQueryVariables = Exact<{
  filter?: UserFilter | null | undefined;
  orderBy?: UserOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUsersQuery = { users: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, username: string, email: string, emailVerified: boolean, enabled: boolean | null, locked: boolean | null, lockedUntil: string | null, failedAttempts: number | null, version: string, createdAt: string, updatedAt: string | null } }> } };

export type ConsoleUserQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleUserQuery = { user: { id: string, username: string, email: string, emailVerified: boolean, enabled: boolean | null, locked: boolean | null, lockedUntil: string | null, failedAttempts: number | null, version: string, givenName: string | null, familyName: string | null, middleName: string | null, nickname: string | null, profile: string | null, picture: string | null, website: string | null, birthdate: string | null, locale: string | null, theme: string | null, createdAt: string, updatedAt: string | null } | null };

export type ConsoleCreateUserMutationVariables = Exact<{
  input: CreateUserInput;
}>;


export type ConsoleCreateUserMutation = { createUser: { userId: string, version: string } };

export type ConsoleUpdateUserMutationVariables = Exact<{
  input: UpdateUserInput;
}>;


export type ConsoleUpdateUserMutation = { updateUser: { userId: string, version: string } };

export type ConsoleEnableUserMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleEnableUserMutation = { enableUser: { userId: string, version: string } };

export type ConsoleDisableUserMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleDisableUserMutation = { disableUser: { userId: string, version: string } };

export type ConsoleUnlockUserMutationVariables = Exact<{
  input: UnlockUserInput;
}>;


export type ConsoleUnlockUserMutation = { unlockUser: { userId: string, version: string } };

export type ConsoleUserGroupsQueryVariables = Exact<{
  userId: string | number;
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserGroupsQuery = { user: { id: string, groups: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } } | null };

export class TypedDocumentString<TResult, TVariables>
  extends String
  implements DocumentTypeDecoration<TResult, TVariables>
{
  __apiType?: NonNullable<DocumentTypeDecoration<TResult, TVariables>['__apiType']>;
  private value: string;
  public __meta__?: Record<string, any> | undefined;

  constructor(value: string, __meta__?: Record<string, any> | undefined) {
    super(value);
    this.value = value;
    this.__meta__ = __meta__;
  }

  override toString(): string & DocumentTypeDecoration<TResult, TVariables> {
    return this.value;
  }
}

export const ConsoleBootstrapDocument = new TypedDocumentString(`
    query ConsoleBootstrap {
  effectivePermissions {
    role
    requestableScopes
    grantedScopes
    effectiveScopes
    authentication {
      acr
      authTime
      aal2
      recent
    }
  }
  instanceInfo {
    name
    environment
    issuer
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleBootstrapQuery, ConsoleBootstrapQueryVariables>;
export const ConsoleResourcesDocument = new TypedDocumentString(`
    query ConsoleResources($filter: ResourceFilter, $orderBy: ResourceOrder, $first: Int, $after: String, $last: Int, $before: String) {
  resources(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        name
        uri
        enabled
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourcesQuery, ConsoleResourcesQueryVariables>;
export const ConsoleResourceDocument = new TypedDocumentString(`
    query ConsoleResource($id: ID!) {
  resource(id: $id) {
    id
    name
    uri
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourceQuery, ConsoleResourceQueryVariables>;
export const ConsolePermissionRolesDocument = new TypedDocumentString(`
    query ConsolePermissionRoles($id: ID!, $first: Int, $after: String, $last: Int, $before: String) {
  permission: scope(id: $id) {
    id
    roles(first: $first, after: $after, last: $last, before: $before) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        node {
          id
          name
          builtIn
          enabled
          description
          names {
            locale
            value
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionRolesQuery, ConsolePermissionRolesQueryVariables>;
export const ConsolePermissionDocument = new TypedDocumentString(`
    query ConsolePermission($id: ID!, $includeResource: Boolean!) {
  permission: scope(id: $id) {
    id
    resourceId
    code
    name
    description
    builtIn
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
    resource @include(if: $includeResource) {
      id
      uri
      name
      enabled
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionQuery, ConsolePermissionQueryVariables>;
export const ConsoleCreatePermissionDocument = new TypedDocumentString(`
    mutation ConsoleCreatePermission($input: CreateScopeInput!) {
  createPermission: createScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreatePermissionMutation, ConsoleCreatePermissionMutationVariables>;
export const ConsoleUpdatePermissionDocument = new TypedDocumentString(`
    mutation ConsoleUpdatePermission($input: UpdateScopeInput!) {
  updatePermission: updateScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdatePermissionMutation, ConsoleUpdatePermissionMutationVariables>;
export const ConsoleEnablePermissionDocument = new TypedDocumentString(`
    mutation ConsoleEnablePermission($input: ScopeStateInput!) {
  enablePermission: enableScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnablePermissionMutation, ConsoleEnablePermissionMutationVariables>;
export const ConsoleDisablePermissionDocument = new TypedDocumentString(`
    mutation ConsoleDisablePermission($input: ScopeStateInput!) {
  disablePermission: disableScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisablePermissionMutation, ConsoleDisablePermissionMutationVariables>;
export const ConsoleScopesDocument = new TypedDocumentString(`
    query ConsoleScopes($filter: ScopeFilter, $first: Int, $after: String, $last: Int, $before: String) {
  scopes(
    filter: $filter
    orderBy: CODE_ASC
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        code
        name
        description
        names {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleScopesQuery, ConsoleScopesQueryVariables>;
export const ConsolePermissionsDocument = new TypedDocumentString(`
    query ConsolePermissions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String, $includeResource: Boolean!) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        resourceId
        code
        name
        description
        builtIn
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
        resource @include(if: $includeResource) {
          id
          uri
          name
          enabled
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionsQuery, ConsolePermissionsQueryVariables>;
export const ConsoleResourcePermissionsDocument = new TypedDocumentString(`
    query ConsoleResourcePermissions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        code
        name
        description
        builtIn
        enabled
        createdAt
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourcePermissionsQuery, ConsoleResourcePermissionsQueryVariables>;
export const InstanceDashboardDocument = new TypedDocumentString(`
    query InstanceDashboard($timeZone: String!, $includeUsers: Boolean!, $includeApplications: Boolean!, $includeSessions: Boolean!, $includeResources: Boolean!) {
  instanceOverview {
    generatedAt
    users(timeZone: $timeZone) @include(if: $includeUsers) {
      total
      enabled
      createdLast7Days
      registrations {
        date
        count
      }
    }
    applications @include(if: $includeApplications) {
      total
      enabled
      builtIn
    }
    sessions @include(if: $includeSessions) {
      active
      createdLast24Hours
    }
    resources @include(if: $includeResources) {
      total
      enabled
    }
  }
}
    `) as unknown as TypedDocumentString<InstanceDashboardQuery, InstanceDashboardQueryVariables>;
export const ConsoleUserRolesDocument = new TypedDocumentString(`
    query ConsoleUserRoles($userId: ID!, $enabled: Boolean, $orderBy: UserRoleBindingOrder, $first: Int, $after: String, $last: Int, $before: String, $includeRole: Boolean!) {
  userRoles(
    userId: $userId
    enabled: $enabled
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    userVersion
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        userId
        roleId
        grantedByUserId
        reason
        enabled
        revokedAt
        version
        userVersion
        createdAt
        updatedAt
        role @include(if: $includeRole) {
          id
          name
          description
          enabled
          names {
            locale
            value
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserRolesQuery, ConsoleUserRolesQueryVariables>;
export const ConsoleUserRoleVersionDocument = new TypedDocumentString(`
    query ConsoleUserRoleVersion($userId: ID!) {
  userRoles(userId: $userId, first: 1) {
    userVersion
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserRoleVersionQuery, ConsoleUserRoleVersionQueryVariables>;
export const ConsoleUserPermissionsDocument = new TypedDocumentString(`
    query ConsoleUserPermissions($userId: ID!, $resourceId: ID!, $orderBy: EffectivePermissionOrder, $first: Int, $after: String, $last: Int, $before: String) {
  userPermissions(
    userId: $userId
    resourceId: $resourceId
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    userVersion
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        permissionId
        resourceId
        code
        sources {
          bindingId
          roleId
        }
        groupSources {
          groupId
          membershipId
          groupRoleBindingId
          roleId
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserPermissionsQuery, ConsoleUserPermissionsQueryVariables>;
export const ConsoleAssignUserRolesDocument = new TypedDocumentString(`
    mutation ConsoleAssignUserRoles($input: AssignUserRolesInput!) {
  assignUserRoles(input: $input) {
    userId
    userVersion
    bindingIds
    createdCount
    revokedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleAssignUserRolesMutation, ConsoleAssignUserRolesMutationVariables>;
export const ConsoleRevokeUserRolesDocument = new TypedDocumentString(`
    mutation ConsoleRevokeUserRoles($input: RevokeUserRolesInput!) {
  revokeUserRoles(input: $input) {
    userId
    userVersion
    bindingIds
    createdCount
    revokedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleRevokeUserRolesMutation, ConsoleRevokeUserRolesMutationVariables>;
export const ConsoleAuthorizationLabelsDocument = new TypedDocumentString(`
    query ConsoleAuthorizationLabels($ids: [ID!]!) {
  nodes(ids: $ids) {
    id
    __typename
    ... on Scope {
      code
      name
      description
      names {
        locale
        value
      }
      descriptions {
        locale
        value
      }
    }
    ... on Group {
      name
      names {
        locale
        value
      }
    }
    ... on Role {
      name
      description
      names {
        locale
        value
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleAuthorizationLabelsQuery, ConsoleAuthorizationLabelsQueryVariables>;
export const ConsoleGroupsDocument = new TypedDocumentString(`
    query ConsoleGroups($filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  groups(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        builtIn
        name
        description
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupsQuery, ConsoleGroupsQueryVariables>;
export const ConsoleGroupDocument = new TypedDocumentString(`
    query ConsoleGroup($id: ID!) {
  group(id: $id) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupQuery, ConsoleGroupQueryVariables>;
export const ConsoleGroupMembersDocument = new TypedDocumentString(`
    query ConsoleGroupMembers($groupId: ID!, $filter: GroupMembershipFilter, $orderBy: GroupMembershipOrder, $first: Int, $after: String, $last: Int, $before: String, $includeUser: Boolean!) {
  group(id: $groupId) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    version
    members(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          groupId
          userId
          grantedByUserId
          enabled
          revokedAt
          version
          createdAt
          updatedAt
          user @include(if: $includeUser) {
            id
            username
            email
            enabled
            locked
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupMembersQuery, ConsoleGroupMembersQueryVariables>;
export const ConsoleGroupRolesDocument = new TypedDocumentString(`
    query ConsoleGroupRoles($groupId: ID!, $filter: GroupRoleFilter, $orderBy: GroupRoleOrder, $first: Int, $after: String, $last: Int, $before: String, $includeRole: Boolean!) {
  group(id: $groupId) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    version
    roles(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          groupId
          roleId
          grantedByUserId
          enabled
          revokedAt
          version
          createdAt
          updatedAt
          role @include(if: $includeRole) {
            id
            name
            builtIn
            description
            names {
              locale
              value
            }
            descriptions {
              locale
              value
            }
            enabled
            version
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupRolesQuery, ConsoleGroupRolesQueryVariables>;
export const ConsoleGroupRoleIdsDocument = new TypedDocumentString(`
    query ConsoleGroupRoleIds($groupId: ID!, $first: Int!, $after: String) {
  group(id: $groupId) {
    id
    version
    roles(
      filter: { enabled: true }
      orderBy: ROLE_NAME_ASC
      first: $first
      after: $after
    ) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          roleId
          enabled
          revokedAt
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupRoleIdsQuery, ConsoleGroupRoleIdsQueryVariables>;
export const ConsoleCreateGroupDocument = new TypedDocumentString(`
    mutation ConsoleCreateGroup($input: CreateGroupInput!) {
  createGroup(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateGroupMutation, ConsoleCreateGroupMutationVariables>;
export const ConsoleUpdateGroupDocument = new TypedDocumentString(`
    mutation ConsoleUpdateGroup($input: UpdateGroupInput!) {
  updateGroup(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateGroupMutation, ConsoleUpdateGroupMutationVariables>;
export const ConsoleAddGroupMemberDocument = new TypedDocumentString(`
    mutation ConsoleAddGroupMember($input: AddGroupMemberInput!) {
  addGroupMember(input: $input) {
    groupId
    userId
    membershipId
    groupVersion
    membershipVersion
  }
}
    `) as unknown as TypedDocumentString<ConsoleAddGroupMemberMutation, ConsoleAddGroupMemberMutationVariables>;
export const ConsoleRemoveGroupMemberDocument = new TypedDocumentString(`
    mutation ConsoleRemoveGroupMember($input: RemoveGroupMemberInput!) {
  removeGroupMember(input: $input) {
    groupId
    userId
    membershipId
    groupVersion
    membershipVersion
  }
}
    `) as unknown as TypedDocumentString<ConsoleRemoveGroupMemberMutation, ConsoleRemoveGroupMemberMutationVariables>;
export const ConsoleSetGroupRolesDocument = new TypedDocumentString(`
    mutation ConsoleSetGroupRoles($input: SetGroupRolesInput!) {
  setGroupRoles(input: $input) {
    groupId
    groupVersion
    roleIds
    addedCount
    removedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetGroupRolesMutation, ConsoleSetGroupRolesMutationVariables>;
export const ConsoleSetGroupEnabledDocument = new TypedDocumentString(`
    mutation ConsoleSetGroupEnabled($input: SetGroupEnabledInput!) {
  setGroupEnabled(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetGroupEnabledMutation, ConsoleSetGroupEnabledMutationVariables>;
export const ConsoleDeleteGroupDocument = new TypedDocumentString(`
    mutation ConsoleDeleteGroup($input: GroupStateInput!) {
  deleteGroup(input: $input) {
    groupId
    deleted
  }
}
    `) as unknown as TypedDocumentString<ConsoleDeleteGroupMutation, ConsoleDeleteGroupMutationVariables>;
export const ConsolePermissionOptionsDocument = new TypedDocumentString(`
    query ConsolePermissionOptions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        resourceId
        code
        name
        description
        builtIn
        enabled
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionOptionsQuery, ConsolePermissionOptionsQueryVariables>;
export const ConsoleRoleGroupsDocument = new TypedDocumentString(`
    query ConsoleRoleGroups($roleId: ID!, $filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  role(id: $roleId) {
    id
    groups(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          builtIn
          name
          description
          names {
            locale
            value
          }
          descriptions {
            locale
            value
          }
          enabled
          updatedAt
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleGroupsQuery, ConsoleRoleGroupsQueryVariables>;
export const ConsoleRolesDocument = new TypedDocumentString(`
    query ConsoleRoles($filter: RoleFilter, $orderBy: RoleOrder, $first: Int, $after: String, $last: Int, $before: String) {
  roles(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        name
        description
        builtIn
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRolesQuery, ConsoleRolesQueryVariables>;
export const ConsoleRoleDocument = new TypedDocumentString(`
    query ConsoleRole($id: ID!) {
  role(id: $id) {
    id
    name
    description
    builtIn
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleQuery, ConsoleRoleQueryVariables>;
export const ConsoleCreateRoleDocument = new TypedDocumentString(`
    mutation ConsoleCreateRole($input: CreateRoleInput!) {
  createRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateRoleMutation, ConsoleCreateRoleMutationVariables>;
export const ConsoleUpdateRoleDocument = new TypedDocumentString(`
    mutation ConsoleUpdateRole($input: UpdateRoleInput!) {
  updateRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateRoleMutation, ConsoleUpdateRoleMutationVariables>;
export const ConsoleEnableRoleDocument = new TypedDocumentString(`
    mutation ConsoleEnableRole($input: RoleStateInput!) {
  enableRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnableRoleMutation, ConsoleEnableRoleMutationVariables>;
export const ConsoleDisableRoleDocument = new TypedDocumentString(`
    mutation ConsoleDisableRole($input: RoleStateInput!) {
  disableRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisableRoleMutation, ConsoleDisableRoleMutationVariables>;
export const ConsoleSetRolePermissionsDocument = new TypedDocumentString(`
    mutation ConsoleSetRolePermissions($input: SetRolePermissionsInput!) {
  setRolePermissions(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetRolePermissionsMutation, ConsoleSetRolePermissionsMutationVariables>;
export const ConsoleRoleUsersDocument = new TypedDocumentString(`
    query ConsoleRoleUsers($roleId: ID!, $enabled: Boolean, $orderBy: UserRoleBindingOrder, $first: Int, $after: String, $last: Int, $before: String, $includeUser: Boolean!) {
  roleUsers(
    roleId: $roleId
    enabled: $enabled
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    userVersion
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        userId
        roleId
        grantedByUserId
        reason
        enabled
        revokedAt
        version
        userVersion
        createdAt
        updatedAt
        user @include(if: $includeUser) {
          id
          username
          email
          enabled
          locked
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleUsersQuery, ConsoleRoleUsersQueryVariables>;
export const ConsoleResourceOptionsDocument = new TypedDocumentString(`
    query ConsoleResourceOptions($filter: ResourceFilter, $first: Int, $after: String) {
  resources(filter: $filter, orderBy: NAME_ASC, first: $first, after: $after) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        uri
        name
        enabled
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourceOptionsQuery, ConsoleResourceOptionsQueryVariables>;
export const ConsoleUsersDocument = new TypedDocumentString(`
    query ConsoleUsers($filter: UserFilter, $orderBy: UserOrder, $first: Int, $after: String, $last: Int, $before: String) {
  users(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        username
        email
        emailVerified
        enabled
        locked
        lockedUntil
        failedAttempts
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUsersQuery, ConsoleUsersQueryVariables>;
export const ConsoleUserDocument = new TypedDocumentString(`
    query ConsoleUser($id: ID!) {
  user(id: $id) {
    id
    username
    email
    emailVerified
    enabled
    locked
    lockedUntil
    failedAttempts
    version
    givenName
    familyName
    middleName
    nickname
    profile
    picture
    website
    birthdate
    locale
    theme
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserQuery, ConsoleUserQueryVariables>;
export const ConsoleCreateUserDocument = new TypedDocumentString(`
    mutation ConsoleCreateUser($input: CreateUserInput!) {
  createUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateUserMutation, ConsoleCreateUserMutationVariables>;
export const ConsoleUpdateUserDocument = new TypedDocumentString(`
    mutation ConsoleUpdateUser($input: UpdateUserInput!) {
  updateUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateUserMutation, ConsoleUpdateUserMutationVariables>;
export const ConsoleEnableUserDocument = new TypedDocumentString(`
    mutation ConsoleEnableUser($input: UserStateInput!) {
  enableUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnableUserMutation, ConsoleEnableUserMutationVariables>;
export const ConsoleDisableUserDocument = new TypedDocumentString(`
    mutation ConsoleDisableUser($input: UserStateInput!) {
  disableUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisableUserMutation, ConsoleDisableUserMutationVariables>;
export const ConsoleUnlockUserDocument = new TypedDocumentString(`
    mutation ConsoleUnlockUser($input: UnlockUserInput!) {
  unlockUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUnlockUserMutation, ConsoleUnlockUserMutationVariables>;
export const ConsoleUserGroupsDocument = new TypedDocumentString(`
    query ConsoleUserGroups($userId: ID!, $filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    groups(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          builtIn
          name
          description
          names {
            locale
            value
          }
          descriptions {
            locale
            value
          }
          enabled
          version
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserGroupsQuery, ConsoleUserGroupsQueryVariables>;