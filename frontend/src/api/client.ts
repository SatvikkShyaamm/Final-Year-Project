import axios from 'axios'

/**
 * Single axios instance for all REST calls to the backend.
 *
 * Module 2 will add a request interceptor here to attach the JWT
 * (Authorization: Bearer <token>) and a response interceptor to handle
 * 401s by redirecting to /login. Nothing about that belongs in individual
 * page components.
 */
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
})

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
export const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL ?? 'ws://localhost:8000'
