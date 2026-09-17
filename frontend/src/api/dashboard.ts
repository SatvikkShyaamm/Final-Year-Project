import { apiClient } from './client'
import type {
  DashboardAnalytics,
  DashboardOverview,
  LockedAccountsResponse,
  LockoutClearedResponse,
} from '../types'

/**
 * Typed wrappers over the Module 8 dashboard-aggregation endpoints. The live
 * `/ws/dashboard` client lives separately in `ws/dashboardSocket.ts` (a
 * push-only "something changed" signal, not a data source of its own).
 */

export async function getDashboardOverview(): Promise<DashboardOverview> {
  const { data } = await apiClient.get<DashboardOverview>('/api/v1/dashboard/overview')
  return data
}

export async function getDashboardAnalytics(days = 14): Promise<DashboardAnalytics> {
  const { data } = await apiClient.get<DashboardAnalytics>('/api/v1/dashboard/analytics', {
    params: { days },
  })
  return data
}

export async function listLockedAccounts(): Promise<LockedAccountsResponse> {
  const { data } = await apiClient.get<LockedAccountsResponse>('/api/v1/dashboard/lockouts')
  return data
}

export async function clearAccountLockout(userId: number): Promise<LockoutClearedResponse> {
  const { data } = await apiClient.delete<LockoutClearedResponse>(
    `/api/v1/dashboard/lockouts/${userId}`,
  )
  return data
}
