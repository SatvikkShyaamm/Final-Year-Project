/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_WS_BASE_URL: string
  /** Module 7 Section 18 (2026-09-15) — the passive-detection heartbeat's
   * cadence, in seconds. Optional; defaults to 20 (SessionProvider) when
   * unset, matching the backend's own `heartbeat_interval_seconds` default. */
  readonly VITE_HEARTBEAT_INTERVAL_SECONDS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
