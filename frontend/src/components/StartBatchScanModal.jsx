import { useState } from 'react'
import { Zap, AlertCircle, CheckCircle2, X } from 'lucide-react'

const API_BASE = import.meta.env.DEV ? '/api' : ''

export default function StartBatchScanModal({ scanId, subdomains, scanMode, onStart, onClose }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  // Detailed is the default mode below, and it caps parallel scans at 5 —
  // this needs to start in sync with that cap. It previously defaulted to
  // 10 regardless of mode, so the slider showed 10 on first open and only
  // corrected to 5 once the Detailed button was explicitly clicked.
  const [maxConcurrent, setMaxConcurrent] = useState(5)
  const [batchMode, setBatchMode] = useState('detailed')
  // Off by default — VirusTotal alone paces every call to a real 16s
  // minimum spacing, process-wide, so for a large batch this is the single
  // biggest lever over total run time. Explicit opt-in rather than always-on.
  const [includeReputation, setIncludeReputation] = useState(false)

  const abuseipdbKey = localStorage.getItem('recon_abuseipdb_key') || ''
  const virustotalKey = localStorage.getItem('recon_virustotal_key') || ''

  const subdomainList = (subdomains || []).map(s => typeof s === 'string' ? s : s.subdomain || s)
  const uniqueSubdomains = [...new Set(subdomainList)]

  const handleStartBatch = async () => {
    if (uniqueSubdomains.length === 0) {
      setError('No subdomains found to scan')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const token = localStorage.getItem('recon_token')
      const res = await fetch(`${API_BASE}/scan/start-subdomain-batch`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          parent_scan_id: scanId,
          subdomains: uniqueSubdomains,
          mode: batchMode,
          max_concurrent: maxConcurrent,
          include_reputation: batchMode === 'detailed' ? includeReputation : false,
          abuseipdb_api_key: abuseipdbKey || undefined,
          virustotal_api_key: virustotalKey || undefined
        })
      })

      if (res.ok) {
        const data = await res.json()
        if (onStart) {
          onStart(data.batch_id)
        }
      } else {
        const errData = await res.json()
        setError(errData.detail || 'Failed to start batch scan')
      }
    } catch (err) {
      setError(err.message)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="natural-card rounded-xl max-w-4xl w-full shadow-2xl animate-fade-in">
        <div className="bg-gradient-to-r from-teal-50 to-cyan-50 border-b border-teal-200 px-8 py-7 flex items-center justify-between rounded-t-xl">
          <div className="flex items-center gap-3">
            <Zap className="w-8 h-8 text-teal-600" />
            <h2 className="text-xl font-bold text-slate-900">Scan All Subdomains</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-white rounded transition-colors"
          >
            <X className="w-5 h-5 text-slate-600" />
          </button>
        </div>

        <div className="px-8 py-8 space-y-6">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-blue-900 mb-1">
                  {uniqueSubdomains.length} Unique Subdomains Found
                </p>
                <p className="text-sm text-blue-800">
                  Full security audit will run on each subdomain with rate limiting to respect API limits.
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <p className="text-sm font-medium text-slate-700">Subdomains to Scan:</p>
              <div className="bg-slate-50 rounded-lg p-4 h-64 overflow-y-auto border border-slate-200">
                <div className="space-y-1.5 columns-1 sm:columns-2 gap-4">
                  {uniqueSubdomains.map((sub, idx) => (
                    <p key={idx} className="text-sm text-slate-700 font-mono truncate break-inside-avoid">
                      • {sub}
                    </p>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <div className="space-y-2">
                <label className="block text-sm font-medium text-slate-700">Scan Mode</label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => setBatchMode('fast')}
                    className={`px-4 py-3 rounded-lg font-medium transition-all ${
                      batchMode === 'fast'
                        ? 'bg-teal-600 text-white shadow-md'
                        : 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                    }`}
                  >
                    Fast
                  </button>
                  <button
                    onClick={() => {
                      setBatchMode('detailed')
                      setMaxConcurrent(c => Math.min(c, 5))
                    }}
                    className={`px-4 py-3 rounded-lg font-medium transition-all ${
                      batchMode === 'detailed'
                        ? 'bg-teal-600 text-white shadow-md'
                        : 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                    }`}
                  >
                    Detailed
                  </button>
                </div>
                <p className="text-xs text-slate-600">
                  {batchMode === 'detailed'
                    ? 'Runs the full module set on every subdomain: port scan, directory enum, reverse DNS, email harvesting, nested subdomain lookup, cloud provider ID, plus AbuseIPDB & VirusTotal reputation checks (if enabled below).'
                    : 'Passive checks only on every subdomain: DNS, WHOIS, SSL, headers, tech stack, geo/IP info. No port scanning, no reputation lookups.'}
                </p>
              </div>

              {batchMode === 'detailed' && (
                <label className="flex items-start gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg cursor-pointer hover:bg-slate-100 transition-colors">
                  <input
                    type="checkbox"
                    checked={includeReputation}
                    onChange={(e) => setIncludeReputation(e.target.checked)}
                    className="mt-0.5 w-4 h-4 accent-teal-600 cursor-pointer"
                  />
                  <span>
                    <span className="block text-sm font-medium text-slate-700">Include reputation checks (AbuseIPDB &amp; VirusTotal)</span>
                    <span className="block text-xs text-slate-600 mt-0.5">
                      VirusTotal paces every request to a 16-second minimum gap, shared across the whole batch — for a large subdomain list this is usually the single biggest factor in total run time. Leave unchecked for a much faster sweep; tick it only if you specifically need reputation data.
                    </span>
                  </span>
                </label>
              )}

              <div className="space-y-2">
                <label className="block text-sm font-medium text-slate-700">
                  Parallel Scans: <span className="text-teal-600 font-bold">{maxConcurrent}</span>
                </label>
                <input
                  type="range"
                  min="1"
                  max={batchMode === 'detailed' ? 5 : 10}
                  value={maxConcurrent}
                  onChange={(e) => setMaxConcurrent(parseInt(e.target.value))}
                  className="w-full h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-teal-600"
                />
                <p className="text-xs text-slate-600">
                  {batchMode === 'detailed'
                    ? 'Detailed mode caps at 5 parallel scans — each one spawns port scans and subprocess-based subdomain tools. Recommended: 3-5'
                    : 'Higher values = faster but may use more resources. Recommended: 3-5'}
                </p>
              </div>

              {error && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <p className="text-sm text-red-700 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" />
                    {error}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="px-8 py-5 border-t border-slate-200 bg-slate-50 rounded-b-xl flex gap-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="flex-1 px-4 py-2 bg-slate-300 hover:bg-slate-400 disabled:opacity-50 text-slate-900 rounded-lg transition-colors font-medium"
          >
            Cancel
          </button>
          <button
            onClick={handleStartBatch}
            disabled={loading}
            className="flex-1 px-4 py-2 bg-teal-600 hover:bg-teal-700 disabled:opacity-50 text-white rounded-lg transition-colors font-medium flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Starting...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                Start Batch Scan
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
