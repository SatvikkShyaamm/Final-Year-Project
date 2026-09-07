import { useContext } from 'react'
import { SessionContext } from './context'

/** Access the caller's session state. Must be inside <SessionProvider>. */
export function useSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) {
    throw new Error('useSession must be used within a <SessionProvider>')
  }
  return ctx
}
