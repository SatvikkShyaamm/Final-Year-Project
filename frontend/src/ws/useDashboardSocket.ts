import { useEffect, useRef, useState } from 'react'
import { getToken } from '../auth/tokenStore'
import { DashboardSocket } from './dashboardSocket'
import type { DashboardWsMessage } from '../types'

/**
 * Connects one admin page to the live `/ws/dashboard` feed (Module 8) for
 * the lifetime of that page, and returns a `tick` that increments on every
 * message received — a page's own polling `useEffect` adds `tick` to its
 * dependency array to refetch immediately on a live event, in addition to
 * (not instead of) its regular interval. Never returns data of its own: the
 * page always re-reads its real state from REST.
 */
export function useDashboardSocket(): { tick: number; lastMessage: DashboardWsMessage | null } {
  const [tick, setTick] = useState(0)
  const [lastMessage, setLastMessage] = useState<DashboardWsMessage | null>(null)
  const socketRef = useRef<DashboardSocket | null>(null)

  useEffect(() => {
    const token = getToken()
    if (!token) return

    const socket = new DashboardSocket(token, {
      onMessage: (message) => {
        setLastMessage(message)
        setTick((n) => n + 1)
      },
    })
    socketRef.current = socket
    socket.connect()

    return () => {
      socket.close()
      socketRef.current = null
    }
  }, [])

  return { tick, lastMessage }
}
