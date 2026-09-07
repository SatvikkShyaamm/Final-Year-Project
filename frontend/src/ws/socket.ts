/**
 * Session signalling WebSocket client — Module 3.
 *
 * Mirrors the base paper's client behaviour: the socket opening *is* the
 * session opening (server-side FSM S1 -> S2), the socket closing *is* the
 * session closing. It carries the Module 2 access token as a query param
 * (browsers can't set headers on a WebSocket) and sends a small ping every
 * few seconds so the backend can tell a live socket from a zombie one.
 *
 * Reconnect policy: an *unexpected* drop (network blip, backend restart) is
 * retried with capped exponential backoff. An *explicit* end — the server
 * sent `session.terminated` (logout / admin / timeout / risk) — is final; the
 * caller decides what happens next.
 */
import { WS_BASE_URL } from '../api/client'
import type { SessionSocketStatus } from '../types'

export interface SessionSocketHandlers {
  onStatusChange?: (status: SessionSocketStatus) => void
  onEstablished?: (sessionId: string) => void
  onTerminated?: (reason: string) => void
  onMessage?: (message: Record<string, unknown>) => void
}

const PING_INTERVAL_MS = 15_000
const MAX_BACKOFF_MS = 30_000

export class SessionSocket {
  private ws: WebSocket | null = null
  private readonly token: string
  private readonly handlers: SessionSocketHandlers
  private pingTimer: number | null = null
  private reconnectTimer: number | null = null
  private reconnectAttempts = 0
  private stopped = false
  private status: SessionSocketStatus = 'idle'

  constructor(token: string, handlers: SessionSocketHandlers = {}) {
    this.token = token
    this.handlers = handlers
  }

  connect(): void {
    this.stopped = false
    this.setStatus('connecting')

    const url = `${WS_BASE_URL}/api/v1/ws/session?token=${encodeURIComponent(this.token)}`
    const ws = new WebSocket(url)
    this.ws = ws

    ws.onopen = () => {
      this.reconnectAttempts = 0
      this.setStatus('connected')
      this.startPing()
    }

    ws.onmessage = (event) => {
      let message: Record<string, unknown>
      try {
        message = JSON.parse(event.data as string)
      } catch {
        return
      }
      this.handlers.onMessage?.(message)

      if (message.type === 'session.established' && typeof message.session_id === 'string') {
        this.handlers.onEstablished?.(message.session_id)
      } else if (message.type === 'session.terminated') {
        // Server-driven end — do not reconnect after this close.
        this.stopped = true
        this.handlers.onTerminated?.(String(message.reason ?? 'terminated'))
      }
    }

    ws.onclose = () => {
      this.stopPing()
      this.ws = null
      if (this.stopped) {
        this.setStatus('idle')
        return
      }
      this.setStatus('disconnected')
      this.scheduleReconnect()
    }

    ws.onerror = () => {
      // A close event always follows; reconnect logic lives there.
    }
  }

  /** Intentional shutdown (logout / auth lost). No reconnect. */
  close(): void {
    this.stopped = true
    this.stopPing()
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
    this.setStatus('idle')
  }

  getStatus(): SessionSocketStatus {
    return this.status
  }

  private setStatus(status: SessionSocketStatus): void {
    if (status === this.status) return
    this.status = status
    this.handlers.onStatusChange?.(status)
  }

  private startPing(): void {
    this.stopPing()
    this.pingTimer = window.setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }))
      }
    }, PING_INTERVAL_MS)
  }

  private stopPing(): void {
    if (this.pingTimer !== null) {
      window.clearInterval(this.pingTimer)
      this.pingTimer = null
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
