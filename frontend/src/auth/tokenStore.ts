/**
 * The single place the JWT is persisted on the client (Module 2).
 *
 * Uses `sessionStorage`, not `localStorage` (changed 2026-09-10 — see
 * Project status.md section 7). `localStorage` is shared across every tab of
 * the same browser for a given origin, so logging a second account into a
 * second tab silently overwrote the first tab's token under the same key;
 * when a server-driven termination then force-logged-out the tab that owned
 * the overwritten token, an unrelated tab's next request could read a
 * stale/cleared value, get a 401, and get hard-navigated to /login too —
 * observed concretely as terminating a user's session from the admin's Live
 * Sessions view sometimes logging the admin out as well.
 *
 * `sessionStorage` is scoped per tab even for the same origin, so each tab's
 * token is fully isolated from every other tab's — this eliminates that
 * collision at its source, no backend change required. The trade-off, taken
 * on purpose: a token no longer survives closing and reopening a tab (a
 * fresh login is required), whereas it used to survive via `localStorage`.
 * Refreshing a tab is unaffected either way — `sessionStorage` survives a
 * same-tab reload, only a full tab close clears it.
 *
 * Dependency-free on purpose so both the axios interceptor (api/client.ts) and
 * the auth context can import it without a cycle. A server-driven session end
 * also clears it (SessionProvider calls AuthContext.forceLogout() on
 * session.terminated — see its doc comment), so a closed-for-cause socket
 * really does mean "logged out," not just "reconnect with the same token."
 */
const TOKEN_KEY = 'ztsaacm.access_token'

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* private-mode / storage disabled — session just won't survive a refresh */
  }
}

export function clearToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}
