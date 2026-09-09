import { useState, useEffect, useContext } from 'react'
import ScanForm from './components/ScanForm'
import ScanProgress from './components/ScanProgress'
import Results from './components/Results'
import SingleModuleView from './components/SingleModuleView'
import LandingPage from './components/LandingPage'
import AuthPage from './components/AuthPage'
import ReconLogo from './components/ReconLogo'
import UserHeaderMenu from './components/UserHeaderMenu'
import AccountModal from './components/AccountModal'
import ScanHistoryModal from './components/ScanHistoryModal'
import StartBatchScanModal from './components/StartBatchScanModal'
import BatchScanProgress from './components/BatchScanProgress'
import BatchScanResults from './components/BatchScanResults'
import FullScanBatchProgress from './components/FullScanBatchProgress'
import FullScanBatchResults from './components/FullScanBatchResults'
import BackgroundScansWidget from './components/BackgroundScansWidget'
import NotificationBell from './components/NotificationBell'
import { BackgroundScansProvider, BackgroundScansContext } from './BackgroundScansContext'
import { NotificationsContext } from './NotificationsContext'
import { AlertCircle, RefreshCw, ArrowLeft } from 'lucide-react'

const API_BASE = import.meta.env.DEV ? '/api' : ''

export default function App() {
  const { addNotification } = useContext(NotificationsContext)

  const [page, setPage] = useState(() => {
    const token = localStorage.getItem('recon_token')
    return token ? 'scan' : 'landing'
  })
  const [user, setUser] = useState(() => {
    try {
      const storedUser = localStorage.getItem('recon_user')
      return storedUser ? JSON.parse(storedUser) : null
    } catch {
      return null
    }
  })
  const [scanVisible, setScanVisible] = useState(false)
  const [status, setStatus] = useState('idle')
  const [scanData, setScanData] = useState(null)
  const [error, setError] = useState(null)
  const [startTime, setStartTime] = useState(null)
  const [scanMode, setScanMode] = useState('fast')
  const [selectedModule, setSelectedModule] = useState(null)

  const [moduleScans, setModuleScans] = useState({})
  const updateModuleScan = (moduleKey, patch) => {
    setModuleScans(prev => ({ ...prev, [moduleKey]: { ...prev[moduleKey], ...patch } }))
  }
  const anyModuleScanning = Object.values(moduleScans).some(m => m?.status === 'scanning')

  const [showBatchModal, setShowBatchModal] = useState(false)
  const [batchId, setBatchId] = useState(null)
  const [batchStatus, setBatchStatus] = useState('idle')
  const [currentScanId, setCurrentScanId] = useState(null)
  const [viewingBatchSubdomain, setViewingBatchSubdomain] = useState(null)

  const [fullBatchId, setFullBatchId] = useState(null)
  const [fullBatchStatus, setFullBatchStatus] = useState('idle')
  const [viewingFullBatchTarget, setViewingFullBatchTarget] = useState(null)
  const { backgroundScans } = useContext(BackgroundScansContext)

  // Any scan currently in flight — single-target, single-module, subdomain
  // batch, or full-scan batch — used to drive the header status pill and
  // to keep the idle-logout timer from firing mid-scan.
  const isAnyScanActive = status === 'scanning' || batchStatus === 'progress' || fullBatchStatus === 'progress' || anyModuleScanning

  const [showAccountModal, setShowAccountModal] = useState(false)
  const [showHistoryModal, setShowHistoryModal] = useState(false)
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const storedHistory = localStorage.getItem('recon_history')
      return storedHistory ? JSON.parse(storedHistory) : []
    } catch {
      return []
    }
  })

  useEffect(() => {
    try {
      const storedUser = localStorage.getItem('recon_user')
      if (storedUser) {
        setUser(JSON.parse(storedUser))
        if (page === 'scan') {
          const userData = JSON.parse(storedUser)
          addNotification(`Logged in as ${userData.email}`, 'login')
        }
      }
    } catch {
      setUser(null)
    }
  }, [page, addNotification])

  const fetchScanHistory = async () => {
    const token = localStorage.getItem('recon_token')
    if (!token) return
    try {
      const res = await fetch(`${API_BASE}/history/scans`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (res.ok) {
        const data = await res.json()
        if (Array.isArray(data)) {
          setScanHistory(data)
          try {
            localStorage.setItem('recon_history', JSON.stringify(data))
          } catch {}
        }
      }
    } catch (err) {
      console.error('Failed to fetch scan history from DB:', err)
    }
  }

  useEffect(() => {
    if (page === 'scan') {
      fetchScanHistory()
    }
  }, [page])

  useEffect(() => {
    const handleScroll = () => {
      window.scrollTo({ top: 0, behavior: 'instant' });
      document.documentElement.scrollTop = 0;
      document.body.scrollTop = 0;
    };
    handleScroll();
    const timer = setTimeout(handleScroll, 50);
    return () => clearTimeout(timer);
  }, [selectedModule, status]);

  useEffect(() => {
    if (page === 'scan') {
      setScanVisible(false)
      const t = setTimeout(() => setScanVisible(true), 20)
      return () => clearTimeout(t)
    }
  }, [page])

  const runScan = async ({ target, mode, includeReputation, module = null, portRange = null, abuseipdbApiKey = null, virustotalApiKey = null }) => {
    const now = Date.now()
    const targetModule = module

    if (targetModule) {
      updateModuleScan(targetModule, { status: 'scanning', error: null, data: null, targets: [target] })
    } else {
      setStatus('scanning')
      setError(null)
      setScanData(null)
      setScanMode(mode)
    }
    setStartTime(now)

    const cleanTarget = target.split(',')[0].trim()
    let scanLabel = ''
    if (module) {
      const moduleNames = {
        'dns_records': 'DNS Records',
        'whois': 'WHOIS Registry',
        'ssl_certificate': 'SSL/TLS Certificate',
        'geo_ip': 'GeoIP Location',
        'http_headers': 'HTTP Headers',
        'web_technologies': 'Web Technologies',
        'abuseipdb': 'AbuseIPDB Reputation',
        'virustotal': 'VirusTotal Threat Intel',
        'port_scan': 'Port Scan',
        'subdomains': 'Subdomain Index',
        'directories': 'Directory Enumeration',
        'reverse_dns': 'Reverse DNS',
        'cloud_provider': 'Cloud Provider Detection',
        'waf_detect': 'WAF Detection',
        'cms_fingerprint': 'CMS Fingerprinting',
        'shodan_intel': 'Shodan Intel',
        'http_availability': 'HTTP/HTTPS Accessibility'
      }
      scanLabel = moduleNames[module] || module
    } else if (mode === 'detailed') {
      scanLabel = 'Deep Check'
    } else {
      scanLabel = 'Standard Check'
    }

    addNotification(`Scan started on ${cleanTarget} (${scanLabel})`, 'scan_started')

    try {
      const cleanTarget = target.split(',')[0].trim()
      const url = `${API_BASE}/scan`
      
      let storedAbuseKey = ''
      let storedVtKey = ''
      try { storedAbuseKey = (localStorage.getItem('recon_abuseipdb_key') || '').trim() } catch {}
      try { storedVtKey = (localStorage.getItem('recon_virustotal_key') || '').trim() } catch {}

      const effectiveAbuseKey = (abuseipdbApiKey || storedAbuseKey) || null
      const effectiveVtKey = (virustotalApiKey || storedVtKey) || null

      const payload = {
        target: cleanTarget,
        mode,
        include_reputation: includeReputation,
        module: module || selectedModule,
        port_range: portRange,
        abuseipdb_api_key: effectiveAbuseKey,
        virustotal_api_key: effectiveVtKey
      }

      const token = localStorage.getItem('recon_token')
      if (!token) {
        setPage('auth')
        return
      }

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      })

      if (response.status === 401) {
        localStorage.removeItem('recon_token')
        localStorage.removeItem('recon_user')
        setUser(null)
        setPage('auth')
        return
      }

      const data = await response.json()

      if (!response.ok) {
        const detail = typeof data?.detail === 'string' ? data.detail : JSON.stringify(data?.detail || data)
        const message = detail || `Scan request failed (${response.status})`
        if (targetModule) {
          updateModuleScan(targetModule, { status: 'error', error: message })
        } else {
          setError(message)
          setStatus('error')
        }
        return
      }

      if (targetModule) {
        updateModuleScan(targetModule, { status: 'done', data, error: null })
      } else {
        setScanData(data)
        setStatus('done')
      }

      const duration = Math.round((Date.now() - now) / 1000)
      addNotification(`Scan finished on ${cleanTarget} (${duration}s)`, 'scan_finished')

      fetchScanHistory()
    } catch (e) {
      if (targetModule) {
        updateModuleScan(targetModule, { status: 'error', error: e.message })
      } else {
        setError(e.message)
        setStatus('error')
      }
    }
  }

  const runFullScanBatch = async ({ targets, mode, includeReputation, maxConcurrent, abuseipdbApiKey = null, virustotalApiKey = null }) => {
    setScanMode(mode)
    addNotification(`Batch scan started on ${targets.length} target${targets.length === 1 ? '' : 's'} (${mode === 'deep' ? 'Deep' : 'Standard'} Check)`, 'scan_started')

    try {
      const token = localStorage.getItem('recon_token')
      if (!token) {
        setPage('auth')
        return
      }

      let storedAbuseKey = ''
      let storedVtKey = ''
      try { storedAbuseKey = (localStorage.getItem('recon_abuseipdb_key') || '').trim() } catch {}
      try { storedVtKey = (localStorage.getItem('recon_virustotal_key') || '').trim() } catch {}

      const response = await fetch(`${API_BASE}/scan/full-batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          targets,
          mode,
          include_reputation: includeReputation,
          max_concurrent: maxConcurrent,
          abuseipdb_api_key: (abuseipdbApiKey || storedAbuseKey) || null,
          virustotal_api_key: (virustotalApiKey || storedVtKey) || null,
        }),
      })

      if (response.status === 401) {
        localStorage.removeItem('recon_token')
        localStorage.removeItem('recon_user')
        setUser(null)
        setPage('auth')
        return
      }

      const data = await response.json()

      if (!response.ok) {
        const detail = typeof data?.detail === 'string' ? data.detail : JSON.stringify(data?.detail || data)
        setError(detail || `Batch scan request failed (${response.status})`)
        setStatus('error')
        return
      }

      setFullBatchId(data.batch_id)
      setFullBatchStatus('progress')
    } catch (e) {
      setError(e.message)
      setStatus('error')
    }
  }

  const runModuleBatchScan = async (targets, apiKey, module = 'abuseipdb') => {
    const targetModule = module
    updateModuleScan(targetModule, { status: 'scanning', error: null, data: null, targets })

    const moduleLabel = module === 'virustotal' ? 'VirusTotal' : 'AbuseIPDB'
    addNotification(`Batch check started on ${targets.length} targets (${moduleLabel})`, 'scan_started')

    try {
      const token = localStorage.getItem('recon_token')
      if (!token) {
        setPage('auth')
        return
      }

      const response = await fetch(`${API_BASE}/scan/module-batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          targets,
          module,
          abuseipdb_api_key: module === 'abuseipdb' ? (apiKey || null) : null,
          virustotal_api_key: module === 'virustotal' ? (apiKey || null) : null,
        }),
      })

      if (response.status === 401) {
        localStorage.removeItem('recon_token')
        localStorage.removeItem('recon_user')
        setUser(null)
        setPage('auth')
        return
      }

      const data = await response.json()

      if (!response.ok) {
        const detail = typeof data?.detail === 'string' ? data.detail : JSON.stringify(data?.detail || data)
        updateModuleScan(targetModule, { status: 'error', error: detail || `Batch check failed (${response.status})` })
        return
      }

      updateModuleScan(targetModule, { status: 'done', data, error: null })
      addNotification(`Batch check finished on ${targets.length} targets`, 'scan_finished')
    } catch (e) {
      updateModuleScan(targetModule, { status: 'error', error: e.message })
    }
  }

  const reset = () => {
    setStatus('idle')
    setScanData(null)
    setError(null)
    setBatchId(null)
    setBatchStatus('idle')
    setViewingBatchSubdomain(null)
    setBatchStatus('idle')
    setSelectedModule(null)
    setFullBatchId(null)
    setFullBatchStatus('idle')
    setViewingFullBatchTarget(null)
  }

  const [sessionExpiredReason, setSessionExpiredReason] = useState('')

  useEffect(() => {
    if (page !== 'scan') return

    const IDLE_TIMEOUT_MS = 30 * 60 * 1000
    const LAST_ACTIVITY_KEY = 'recon_last_activity'
    let idleTimer = null

    const updateLastActivity = () => {
      localStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString())
    }

    const checkAndSetupTimer = () => {
      if (idleTimer) clearTimeout(idleTimer)

      const lastActivityStr = localStorage.getItem(LAST_ACTIVITY_KEY)
      if (!lastActivityStr) {
        updateLastActivity()
        idleTimer = setTimeout(logoutIfNotScanning, IDLE_TIMEOUT_MS)
        return
      }

      const lastActivity = parseInt(lastActivityStr, 10)
      const now = Date.now()
      const timeSinceLastActivity = now - lastActivity

      if (timeSinceLastActivity >= IDLE_TIMEOUT_MS) {
        console.warn('User was inactive for >30 minutes. Auto logging out...')
        setSessionExpiredReason('Your session expired due to 30 minutes of inactivity. Please log in again.')
        logoutAndClearActivity()
      } else {
        const remainingTime = IDLE_TIMEOUT_MS - timeSinceLastActivity
        updateLastActivity()
        idleTimer = setTimeout(logoutIfNotScanning, IDLE_TIMEOUT_MS)
      }
    }

    const logoutIfNotScanning = () => {
      if (isAnyScanActive) {
        updateLastActivity()
        idleTimer = setTimeout(logoutIfNotScanning, IDLE_TIMEOUT_MS)
      } else {
        logoutAndClearActivity()
      }
    }

    const logoutAndClearActivity = () => {
      setSessionExpiredReason('Your session expired due to inactivity. Please log in again.')
      localStorage.removeItem(LAST_ACTIVITY_KEY)
      handleLogout()
    }

    checkAndSetupTimer()

    let lastReset = Date.now()
    const handleUserActivity = () => {
      const now = Date.now()
      if (now - lastReset > 1000) {
        lastReset = now
        updateLastActivity()
        checkAndSetupTimer()
      }
    }

    const events = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'click']
    events.forEach((evt) => window.addEventListener(evt, handleUserActivity, { passive: true }))

    return () => {
      if (idleTimer) clearTimeout(idleTimer)
      events.forEach((evt) => window.removeEventListener(evt, handleUserActivity))
    }
  }, [page, isAnyScanActive])

  const handleLogout = () => {
    const currentUser = localStorage.getItem('recon_user')
    localStorage.removeItem('recon_token')
    localStorage.removeItem('recon_user')
    localStorage.removeItem('recon_history')
    localStorage.removeItem('recon_abuseipdb_key')
    localStorage.removeItem('recon_virustotal_key')
    localStorage.removeItem('recon_last_activity')

    setUser(null)
    setPage('auth')
    setStatus('idle')
    setScanData(null)
    setError(null)
    setBatchId(null)
    setBatchStatus('idle')
    setSelectedModule(null)
    setFullBatchId(null)
    setFullBatchStatus('idle')
    setViewingFullBatchTarget(null)

    if (currentUser) {
      try {
        const userData = JSON.parse(currentUser)
        addNotification(`Logged out: ${userData.email}`, 'login')
      } catch {}
    }
  }

  const handleReScan = (overrides = {}) => {
    if (!scanData || !scanData.target) return
    let abuseipdbApiKey = null
    let virustotalApiKey = null
    try { abuseipdbApiKey = localStorage.getItem('recon_abuseipdb_key') || null } catch {}
    try { virustotalApiKey = localStorage.getItem('recon_virustotal_key') || null } catch {}

    const finalAbuseKey = overrides.abuseipdbApiKey !== undefined ? overrides.abuseipdbApiKey : abuseipdbApiKey
    const finalVtKey = overrides.virustotalApiKey !== undefined ? overrides.virustotalApiKey : virustotalApiKey

    runScan({
      target: scanData.target,
      mode: 'detailed',
      includeReputation: true,
      module: scanData.module || selectedModule || null,
      abuseipdbApiKey: finalAbuseKey,
      virustotalApiKey: finalVtKey
    })
  }

  if (page === 'landing') {
    return <LandingPage onEnter={() => setPage(localStorage.getItem('recon_token') ? 'scan' : 'auth')} />
  }

  if (page === 'auth') {
    return (
      <AuthPage
        onAuthSuccess={() => {
          setSessionExpiredReason('')
          setPage('scan')
        }}
        sessionExpiredReason={sessionExpiredReason}
      />
    )
  }

  return (
    <div
      style={{
        opacity: scanVisible ? 1 : 0,
        transition: 'opacity 0.1s ease',
      }}
      className="min-h-screen bg-gradient-to-tr from-[#bae6fd] via-[#e0f2fe] to-[#ccfbf1] text-natural-text flex flex-col justify-between selection:bg-teal-200 selection:text-teal-950"
    >
      <header className="border-b border-orange-400 bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 sticky top-0 z-50 shadow-md">
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-full bg-orange-700/40 border border-orange-400/50 flex items-center justify-center text-white shadow-inner cursor-pointer" onClick={() => { reset(); setSelectedModule(null); }}>
              <ReconLogo className="w-7 h-7" style={{ color: 'white' }} />
            </div>
            <div>
              <div className="text-xl font-extrabold tracking-wide text-white leading-tight cursor-pointer" onClick={() => { reset(); setSelectedModule(null); }}>
                Reconnaissance Tool
              </div>
              <div className="text-xs text-orange-50 font-bold uppercase tracking-widest mt-1">
                Host Diagnostics
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3.5 py-2 rounded-full border text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              isAnyScanActive
                ? 'bg-orange-700 border-orange-400 text-orange-50'
                : 'bg-orange-700/40 border-orange-400/30 text-orange-100/90'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                isAnyScanActive ? 'bg-orange-300 animate-ping' : 'bg-orange-500/60'
              }`} />
              {status === 'scanning'
                ? 'checking host'
                : anyModuleScanning
                ? 'module check running'
                : batchStatus === 'progress' || fullBatchStatus === 'progress'
                ? 'batch scan running'
                : 'idle'}
            </div>

            <NotificationBell />

            <UserHeaderMenu
              user={user}
              isScanActive={isAnyScanActive}
              onOpenAccount={() => setShowAccountModal(true)}
              onOpenHistory={() => {
                fetchScanHistory()
                setShowHistoryModal(true)
              }}
              onLogout={handleLogout}
            />
          </div>
        </div>
      </header>

      <main className="flex-1 w-full max-w-[1600px] mx-auto px-4 sm:px-8 py-10">
        {selectedModule ? (
          <SingleModuleView
            moduleKey={selectedModule}
            onBack={() => {
              reset()
              setSelectedModule(null)
            }}
            onStartScan={(t, key, pRange) => {
              runScan({
                target: t,
                mode: 'detailed',
                includeReputation: false,
                module: selectedModule,
                portRange: pRange,
                abuseipdbApiKey: selectedModule === 'abuseipdb' ? key : null,
                virustotalApiKey: selectedModule === 'virustotal' ? key : null
              })
            }}
            onStartModuleBatchScan={(targets, key, module) => runModuleBatchScan(targets, key, module)}
            status={moduleScans[selectedModule]?.status || 'idle'}
            scanData={moduleScans[selectedModule]?.data || null}
            error={moduleScans[selectedModule]?.error || null}
            scanningTargets={moduleScans[selectedModule]?.targets || []}
            onReset={() => {
              if (selectedModule) {
                updateModuleScan(selectedModule, { status: 'idle', data: null, error: null })
              }
            }}
          />
        ) : (
          <>
            {status === 'idle' && batchStatus === 'idle' && fullBatchStatus === 'idle' && !viewingBatchSubdomain && !viewingFullBatchTarget && (
              <ScanForm onSubmit={runScan} onSubmitBatch={runFullScanBatch} onSelectModule={setSelectedModule} />
            )}

            {status === 'scanning' && batchStatus !== 'progress' && fullBatchStatus !== 'progress' && <ScanProgress startTime={startTime} mode={scanMode} />}

            {status === 'error' && (
              <div className="max-w-xl mx-auto mt-16 animate-fade-in">
                <div className="border border-red-200 bg-white rounded-2xl p-6 shadow-sm glow-red font-semibold">
                  <div className="flex items-center gap-3 text-red-650 text-red-600 mb-3 font-bold">
                    <AlertCircle className="w-6 h-6 flex-shrink-0" />
                    <span className="text-sm uppercase tracking-wider">Analysis Failed</span>
                  </div>
                  <div className="text-xs text-stone-600 leading-relaxed font-mono bg-stone-50 p-4 border border-stone-200 rounded-lg mb-4 break-all">
                    {error}
                  </div>
                  <button
                    onClick={reset}
                    className="w-full flex items-center justify-center gap-2 py-3 border border-stone-300 hover:border-stone-400 rounded-xl text-sm font-semibold tracking-wider hover:bg-stone-50 transition-all duration-200"
                  >
                    <RefreshCw className="w-4 h-4 text-stone-500" />
                    Reset & Try Again
                  </button>
                </div>
              </div>
            )}

            {batchStatus === 'progress' && batchId ? (
              <BatchScanProgress
                batchId={batchId}
                onComplete={(completedBatchId) => {
                  setBatchStatus('results')
                  setStatus('idle')
                  addNotification(`Batch Scan #${completedBatchId} completed`, 'scan_finished')
                }}
                onBack={reset}
                onBackgroundMode={(completedBatchId) => {
                  reset()
                  addNotification(`Batch Scan #${completedBatchId} moved to background`, 'scan_started')
                }}
              />
            ) : batchStatus === 'results' && batchId ? (
              viewingBatchSubdomain ? (
                <div className="max-w-6xl mx-auto space-y-4 animate-fade-in">
                  <button
                    onClick={() => setViewingBatchSubdomain(null)}
                    className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-lg text-sm font-bold transition-colors shadow-sm"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Batch Results
                  </button>
                  <Results
                    data={viewingBatchSubdomain.scan_result}
                  />
                </div>
              ) : (
                <BatchScanResults
                  batchId={batchId}
                  onClose={reset}
                  onViewSubdomain={(result) => {
                    setViewingBatchSubdomain(result)
                  }}
                />
              )
            ) : fullBatchStatus === 'progress' && fullBatchId ? (
              <FullScanBatchProgress
                batchId={fullBatchId}
                onComplete={(completedBatchId) => {
                  setFullBatchStatus('results')
                  addNotification(`Batch Scan #${completedBatchId} completed`, 'scan_finished')
                }}
                onBack={reset}
                onBackgroundMode={(completedBatchId) => {
                  reset()
                  addNotification(`Batch Scan #${completedBatchId} moved to background`, 'scan_started')
                }}
              />
            ) : fullBatchStatus === 'results' && fullBatchId ? (
              viewingFullBatchTarget ? (
                <div className="max-w-6xl mx-auto space-y-4 animate-fade-in">
                  <button
                    onClick={() => setViewingFullBatchTarget(null)}
                    className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-lg text-sm font-bold transition-colors shadow-sm"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Batch Results
                  </button>
                  <Results
                    data={viewingFullBatchTarget.scan_result}
                    onReset={() => setViewingFullBatchTarget(null)}
                  />
                </div>
              ) : (
                <FullScanBatchResults
                  batchId={fullBatchId}
                  onClose={reset}
                  onViewTarget={(result) => {
                    setViewingFullBatchTarget(result)
                  }}
                />
              )
            ) : (
              status === 'done' && scanData && (
                <Results
                  data={scanData}
                  onReset={reset}
                  onReScan={handleReScan}
                  onBatchScan={() => {
                    setCurrentScanId(scanData.scan_id || scanData.id)
                    setShowBatchModal(true)
                  }}
                />
              )
            )}
          </>
        )}
      </main>

      {showAccountModal && (
        <AccountModal
          user={user}
          onClose={() => setShowAccountModal(false)}
        />
      )}

      {showHistoryModal && (
        <ScanHistoryModal
          history={scanHistory}
          isScanActive={status === 'scanning' || batchStatus === 'progress'}
          onClose={() => setShowHistoryModal(false)}
          onViewScan={(item) => {
            if (status === 'scanning' || batchStatus === 'progress') {
              addNotification('A scan is currently running — finish it or move it to background before viewing history results.', 'error')
              return
            }
            if (item.isBatchScan && item.batch) {
              const batchIdValue = item.batch.id || item.batch.batch_id
              if (batchIdValue) {
                setBatchId(batchIdValue)
                setBatchStatus('results')
                setScanData(null)
                setStatus('idle')
                setShowHistoryModal(false)
              }
            } else if (item.module) {
              updateModuleScan(item.module, { status: 'done', data: item.data, error: null })
              setSelectedModule(item.module)
              setBatchId(null)
              setBatchStatus('idle')
              setShowHistoryModal(false)
            } else {
              setScanData(item.data)
              setStatus('done')
              setSelectedModule(null)
              setBatchId(null)
              setBatchStatus('idle')
              setShowHistoryModal(false)
            }
          }}
        />
      )}

      {showBatchModal && scanData && (
        <>
          {(() => {
            const allSubs = scanData.results?.subdomains?.subdomains || []
            const resolvedSubs = allSubs.filter(s => s.ip && s.ip.trim())

            const uniqueSubdomains = Array.from(new Set(resolvedSubs.map(s => s.subdomain)))
            const uniqueCount = uniqueSubdomains.length

            console.log('Modal rendering with:', {
              scanId: currentScanId || scanData.scan_id || scanData.id,
              totalSubdomains: allSubs.length,
              resolvedSubdomains: resolvedSubs.length,
              uniqueSubdomains: uniqueCount,
              scanMode: scanData.scan_mode
            })

            if (resolvedSubs.length === 0) {
              return (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                  <div className="bg-white rounded-xl p-8 max-w-md shadow-2xl">
                    <p className="text-red-600 font-bold mb-4">Error: No resolved subdomains</p>
                    <p className="text-slate-600 text-sm mb-4">Found {allSubs.length} subdomains but none have resolved IPs. Please try scanning again.</p>
                    <button
                      onClick={() => setShowBatchModal(false)}
                      className="w-full px-4 py-2 bg-teal-600 text-white rounded-lg font-bold"
                    >
                      Close
                    </button>
                  </div>
                </div>
              )
            }

            return (
              <StartBatchScanModal
                scanId={currentScanId || scanData.scan_id || scanData.id || 1}
                subdomains={resolvedSubs}
                scanMode={scanData.scan_mode || 'detailed'}
                onStart={(newBatchId) => {
                  setBatchId(newBatchId)
                  setBatchStatus('progress')
                  setStatus('scanning')
                  setShowBatchModal(false)
                  addNotification(`Batch Scan started with ${uniqueCount} unique subdomains (${scanData.scan_mode || 'detailed'} mode)`, 'scan_started')
                }}
                onClose={() => setShowBatchModal(false)}
              />
            )
          })()}
        </>
      )}

      <footer className="border-t border-slate-300 bg-white/50 py-5 shadow-inner">
        <div className="max-w-6xl mx-auto px-6 text-center">
          <p className="text-xs font-semibold text-slate-500 tracking-wide">
            <span className="font-bold text-slate-700">Note : </span>Perform reconnaissance responsibly and only on assets you own or are explicitly authorized to assess.
          </p>
        </div>
      </footer>

      {page === 'scan' && batchStatus !== 'progress' && fullBatchStatus !== 'progress' && (
        <BackgroundScansWidget
          onScanClick={(clickedBatchId) => {
            if (backgroundScans[clickedBatchId]?.type === 'full-scan') {
              setFullBatchId(clickedBatchId)
              setFullBatchStatus('progress')
            } else {
              setBatchId(clickedBatchId)
              setBatchStatus('progress')
            }
          }}
        />
      )}
    </div>
  )
}

