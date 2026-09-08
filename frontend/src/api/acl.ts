import { apiClient } from './client'
import type { ACLRuleListResponse, ACLStatusResponse } from '../types'

/**
 * Typed wrappers over the Module 4 ACL read endpoints. ACL rules are not
 * client-editable — they follow session lifecycle — so there is no create /
 * delete here; terminating a session (DELETE /sessions/{id}) removes its rule.
 */

export async function listAclRules(
  opts: { includeRemoved?: boolean; state?: string } = {},
): Promise<ACLRuleListResponse> {
  const { data } = await apiClient.get<ACLRuleListResponse>('/api/v1/acl/rules', {
    params: {
      include_removed: opts.includeRemoved ?? false,
      ...(opts.state ? { state: opts.state } : {}),
    },
  })
  return data
}

export async function getAclStatus(): Promise<ACLStatusResponse> {
  const { data } = await apiClient.get<ACLStatusResponse>('/api/v1/acl/status')
  return data
}
