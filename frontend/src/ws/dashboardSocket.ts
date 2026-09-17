/**
 * Admin dashboard live-update socket — Module 8.
 *
 * Push-only from the server's side: it forwards the same Redis pub/sub
 * events sessions/ACL rules/MFA challenges/continuous-evaluation events
 * already publish internally (Modules 3/4/6/7), so the admin dashboard
 * finds out about a change immediately instead of waiting for its own next
 * poll. It is never a source of truth on its own — every page that uses it
 * still reads its real state from the matching REST endpoint; this only
 * decides *when* to read it again sooner than the regular interval.
 *
 * Deliberately much simpler than `SessionSocket` (ws/socket.ts): there is no
 * session lifecycle here, just "reconnect on drop" with capped backoff.
 */
import { WS_BASE_URL } from '../api/client'
import type { DashboardWsMessage } from '../types'

export interface DashboardSocketHandlers {
  onMessage?: (message: DashboardWsMessage) => void
}

const MAX_BACKOFF_MS = 30_000

export class DashboardSocket {
  private ws: WebSocket | null = null
  private readonly token: string
  private readonly handlers: DashboardSocketHandlers
  private reconnectTimer: number | null = null
  private reconnectAttempts = 0
  private stopped = false

  constructor(token: string, handlers: DashboardSocketHandlers = {}) {
    this.token = token
    this.handlers = handlers
  }

  connect(): void {
    this.stopped = false
    const url = `${WS_BASE_URL}/api/v1/ws/dashboard?token=${encodeURIComponent(this.token)}`
    const ws = new WebSocket(url)
    this.ws = ws

    ws.onopen = () => {
      this.reconnectAttempts = 0
    }

    ws.onmessage = (event) => {
      let message: DashboardWsMessage
      try {
        message = JSON.parse(event.data as string)
      } catch {
        return
      }
      this.handlers.onMessage?.(message)
    }

    ws.onclose = () => {
      this.ws = null
      if (!this.stopped) this.scheduleReconnect()
    }

    ws.onerror = () => {
      // A close event always follows; reconnect logic lives there.
    }
  }

  close(): void {
    this.stopped = true
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.onclose = null
      this.ws.onerror = null
      try {
        this.ws.close(1000, 'client shutdown')
      } catch {
        /* already closing */
      }
      this.ws = null
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return
    const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** this.reconnectAttempts)
    this.reconnectAttempts += 1
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      if (!this.stopped) this.connect()
    }, delay)
  }
}
