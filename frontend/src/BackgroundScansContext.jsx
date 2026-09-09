import { createContext, useState, useCallback, useEffect, useRef } from 'react'

export const BackgroundScansContext = createContext()

const API_BASE = import.meta.env.DEV ? '/api' : ''

export function BackgroundScansProvider({ children }) {
  const [backgroundScans, setBackgroundScans] = useState({})
  const [expandedScanId, setExpandedScanId] = useState(null)
  const [progressData, setProgressData] = useState({})
  const [progressErrors, setProgressErrors] = useState({})
  const trackedIds = useRef(new Set())

  const startBackgroundScan = useCallback((batchId, type = 'subdomain') => {
    setBackgroundScans(prev => {
      if (prev[batchId]) return prev
      return { ...prev, [batchId]: { batchId, type, status: 'running', startedAt: new Date() } }
    })
  }, [])

  const removeBackgroundScan = useCallback((batchId) => {
    setBackgroundScans(prev => {
      const newScans = { ...prev }
      delete newScans[batchId]
      return newScans
    })
    setProgressData(prev => {
      const next = { ...prev }
      delete next[batchId]
      return next
    })
    setProgressErrors(prev => {
      const next = { ...prev }
      delete next[batchId]
      return next
    })
    if (expandedScanId === batchId) {
      setExpandedScanId(null)
    }
  }, [expandedScanId])

  const toggleExpandScan = useCallback((batchId) => {
    setExpandedScanId(expandedScanId === batchId ? null : batchId)
  }, [expandedScanId])

  useEffect(() => {
    trackedIds.current = new Set(Object.keys(backgroundScans))
    if (trackedIds.current.size === 0) return

    const token = localStorage.getItem('recon_token')
    if (!token) return

    const fetchAll = async () => {
      for (const batchId of trackedIds.current) {
        const batchType = backgroundScans[batchId]?.type || 'subdomain'
        const endpoint = batchType === 'full-scan'
          ? `${API_BASE}/scan/full-batch-progress/${batchId}`
          : `${API_BASE}/scan/batch-progress/${batchId}`
        try {
          const res = await fetch(endpoint, {
            headers: { 'Authorization': `Bearer ${token}` }
          })
          if (res.ok) {
            const data = await res.json()
            setProgressData(prev => ({ ...prev, [batchId]: data }))
            setProgressErrors(prev => {
              if (!prev[batchId]) return prev
              const next = { ...prev }
              delete next[batchId]
              return next
            })
          } else if (res.status === 401) {
            setProgressErrors(prev => ({ ...prev, [batchId]: 'Your session expired. Please log in again.' }))
          } else {
            let detail = ''
            try { detail = (await res.json()).detail || '' } catch {}
            setProgressErrors(prev => ({ ...prev, [batchId]: `Could not load this batch scan (HTTP ${res.status}). ${detail}`.trim() }))
          }
        } catch (err) {
          setProgressErrors(prev => ({ ...prev, [batchId]: `Failed to reach the server: ${err.message}` }))
          console.error(`Failed to fetch progress for batch ${batchId}:`, err)
        }
      }
    }

    fetchAll()
    const interval = setInterval(fetchAll, 1000)
    return () => clearInterval(interval)
  }, [backgroundScans])

  useEffect(() => {
    const timer = setTimeout(() => {
      setProgressData(prev => {
        const hasCompleted = Object.values(prev).some(p => p.status === 'completed')
        if (hasCompleted) {
          const filtered = { ...prev }
          Object.keys(filtered).forEach(batchId => {
            if (filtered[batchId].status === 'completed') {
              removeBackgroundScan(batchId)
            }
          })
          return filtered
        }
        return prev
      })
    }, 1000)
    return () => clearTimeout(timer)
  }, [progressData, removeBackgroundScan])

  return (
    <BackgroundScansContext.Provider
      value={{
        backgroundScans,
        expandedScanId,
        progressData,
        progressErrors,
        startBackgroundScan,
        removeBackgroundScan,
        toggleExpandScan
      }}
    >
      {children}
    </BackgroundScansContext.Provider>
  )
}
