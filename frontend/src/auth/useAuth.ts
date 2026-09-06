import { useContext } from 'react'
import { AuthContext } from './context'

/** Access the current auth state/actions. Must be inside <AuthProvider>. */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an <AuthProvider>')
  }
  return ctx
}
