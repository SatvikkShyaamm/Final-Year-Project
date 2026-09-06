/**
 * The single place the JWT is persisted on the client (Module 2).
 *
 * Dependency-free on purpose so both the axios interceptor (api/client.ts) and
 * the auth context can import it without a cycle. localStorage keeps the user
 * logged in across refreshes; Module 3 will additionally tie liveness to the
 * WebSocket session, at which point a closed socket also means "logged out".
 */
const TOKEN_KEY = 'ztsaacm.access_token'

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* private-mode / storage disabled — session just won't survive a refresh */
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}
