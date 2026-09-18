import { apiClient } from './client'
import type { SimulationResult, SimulationScenarioKey, SimulationScenariosResponse } from '../types'

/**
 * Typed wrappers over the Module 9 attack-simulation endpoints. Every call
 * triggers real backend logic (Module 7's continuous evaluation, or Module
 * 3's session termination) — see backend/app/services/simulation for
 * exactly which existing function each scenario calls.
 */

export async function listSimulationScenarios(): Promise<SimulationScenariosResponse> {
  const { data } = await apiClient.get<SimulationScenariosResponse>('/api/v1/simulate/scenarios')
  return data
}

export async function runSimulation(
  scenario: SimulationScenarioKey,
  sessionId: string,
): Promise<SimulationResult> {
  const { data } = await apiClient.post<SimulationResult>(`/api/v1/simulate/${scenario}`, {
    session_id: sessionId,
  })
  return data
}
