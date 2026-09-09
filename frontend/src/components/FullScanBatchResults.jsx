import { useState, useEffect } from 'react'
import { Download, Copy, Check, AlertCircle, CheckCircle2, Clock, Server, Globe, ChevronDown, ArrowLeft, ArrowRight } from 'lucide-react'
import { buildBatchScanReportBody } from '../utils/scanReportHtml'

const API_BASE = import.meta.env.DEV ? '/api' : ''

export default function FullScanBatchResults({ batchId, onClose, onViewTarget }) {
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copiedIdx, setCopiedIdx] = useState(null)
  const [filterStatus, setFilterStatus] = useState('all')

  useEffect(() => {
    const token = localStorage.getItem('recon_token')
    if (!token || !batchId) return

    const fetchResults = async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/full-batch-results/${batchId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
        if (res.ok) {
          const data = await res.json()
          setResults(data)
          setError(null)
        }
      } catch (err) {
        setError('Failed to fetch results')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchResults()
  }, [batchId])

  if (loading) {
    return (
      <div className="natural-card p-8 text-center">
        <div className="flex justify-center mb-4">
          <div className="w-8 h-8 border-4 border-teal-200 border-t-teal-600 rounded-full animate-spin"></div>
        </div>
        <p className="text-slate-600">Loading batch scan results...</p>
      </div>
    )
  }

  if (!results) {
    return (
      <div className="natural-card p-8 text-center">
        <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
        <p className="text-slate-600">{error || 'No results found'}</p>
      </div>
    )
  }

  const filteredResults = filterStatus === 'all'
    ? results.results
    : results.results.filter(r => r.status === filterStatus)

  const modeLabel = results.mode === 'deep' || results.mode === 'detailed' ? 'Deep' : 'Standard'

  const downloadHtmlReport = () => {
    const htmlContent = buildBatchScanReportBody(results, {
      title: `${modeLabel} Batch Scan Report`,
      subtitle: `${modeLabel} Batch Full Scan Report`,
    })
    const blob = new Blob([htmlContent], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `full-scan-batch-report-${batchId}.html`
    link.click()
    URL.revokeObjectURL(url)
  }

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text)
    setCopiedIdx(idx)
    setTimeout(() => setCopiedIdx(null), 2000)
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-5 h-5 text-green-600" />
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-600" />
      case 'timeout':
        return <Clock className="w-5 h-5 text-amber-600" />
      default:
        return <Server className="w-5 h-5 text-slate-400" />
    }
  }

  const getStatusBg = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-green-50 border-green-200'
      case 'failed':
        return 'bg-red-50 border-red-200'
      case 'timeout':
        return 'bg-amber-50 border-amber-200'
      default:
        return 'bg-slate-50 border-slate-200'
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
      {onClose && (
        <button
          onClick={onClose}
          className="flex items-center gap-1.5 text-[10px] font-extrabold uppercase tracking-widest text-slate-600 hover:text-slate-900 transition-colors cursor-pointer select-none"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back
        </button>
      )}

      <div className="natural-card rounded-2xl !p-0 overflow-hidden">
        <div className="bg-gradient-to-r from-teal-50 to-cyan-50 px-6 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-3xl font-bold text-slate-900 flex items-center gap-2 mb-2">
                <Globe className="w-8 h-8 text-teal-600" />
                {modeLabel} Batch Scan Results
              </h2>
              <p className="text-slate-700">
                Scanned <span className="font-bold text-teal-600">{results.total_targets}</span> target{results.total_targets === 1 ? '' : 's'} •
                <span className="font-bold text-green-600 mx-1">{results.completed_scans}</span> completed •
                <span className="font-bold text-red-600">{results.failed_scans}</span> failed
              </p>
            </div>
            <button
              onClick={downloadHtmlReport}
              className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-lg transition-colors font-medium"
            >
              <Download className="w-4 h-4" />
              Export HTML
            </button>
          </div>
        </div>
      </div>

      <div className="natural-card rounded-2xl p-6 space-y-4">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider mr-1">Filter:</span>
          {['all', 'completed', 'failed', 'timeout'].map(status => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${
                filterStatus === status
                  ? 'bg-teal-600 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
              }`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>

        <p className="text-xs text-slate-500 flex items-center gap-1.5">
          <ChevronDown className="w-3.5 h-3.5" />
          Click any target below to open its full detailed scan report
        </p>

        <div className="space-y-3 max-h-[32rem] overflow-y-auto">
        {filteredResults.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-slate-500">No results match the selected filter</p>
          </div>
        ) : (
          filteredResults.map((result, idx) => (
            <div
              key={idx}
              className={`border rounded-lg p-4 transition-all ${getStatusBg(result.status)} ${result.scan_result ? 'cursor-pointer hover:shadow-md' : ''}`}
              onClick={() => result.scan_result && onViewTarget && onViewTarget(result)}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  {getStatusIcon(result.status)}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-bold text-slate-900 truncate">{result.target}</p>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          copyToClipboard(result.target, idx)
                        }}
                        className="p-1 hover:bg-white rounded transition-colors flex-shrink-0"
                        title="Copy target"
                      >
                        {copiedIdx === idx ? (
                          <Check className="w-4 h-4 text-green-600" />
                        ) : (
                          <Copy className="w-4 h-4 text-slate-500" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${
                    result.status === 'completed'
                      ? 'bg-green-200 text-green-900'
                      : result.status === 'failed'
                      ? 'bg-red-200 text-red-900'
                      : result.status === 'timeout'
                      ? 'bg-amber-200 text-amber-900'
                      : 'bg-slate-200 text-slate-900'
                  }`}>
                    {result.status}
                  </span>
                  {result.scan_result && (
                    <span className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-600 hover:bg-teal-700 text-white text-xs font-bold rounded-lg transition-colors">
                      View Report
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  )}
                </div>
              </div>

              {result.error && (
                <div className="mt-3 p-2 bg-red-100 border border-red-300 rounded text-sm text-red-800 font-mono">
                  {result.error}
                </div>
              )}
            </div>
          ))
        )}
        </div>

        <div className="border-t border-slate-200 pt-4">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-900 rounded-lg transition-colors font-medium"
          >
            Close Results
          </button>
        </div>
      </div>
    </div>
  )
}
