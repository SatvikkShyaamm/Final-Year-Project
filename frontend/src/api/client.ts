import axios from 'axios'
import { clearToken, getToken } from '../auth/tokenStore'

/**
 * Single axios instance for all REST calls to the backend.
 *
 * Module 2 wires the two interceptors that were reserved here in Module 1:
 *  - request:  attach `Authorization: Bearer <token>` when we have one
 *  - response: on 401, drop the stored token and bounce to /login
 * Individual page components never deal with either concern.
 */
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
})

apiClient.interceptors.request.use((config) => {
  const token = getToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    const path = window.location.pathname
    // Only force a redirect for an expired/invalid session on a page that
    // actually needs auth — not for a failed login attempt on /login itself.
    if (status === 401 && path !== '/login') {
      clearToken()
      window.location.assign('/login')
    }
    return Promise.reject(error)
  },
)

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
export const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL ?? 'ws://localhost:8000'
