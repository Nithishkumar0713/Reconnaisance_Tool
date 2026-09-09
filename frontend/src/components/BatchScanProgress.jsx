import { useState, useEffect, useContext, useRef } from 'react'
import { Activity, AlertCircle, CheckCircle2, Clock, Zap, ArrowLeft, XCircle } from 'lucide-react'
import { BackgroundScansContext } from '../BackgroundScansContext'
import { NotificationsContext } from '../NotificationsContext'

const API_BASE = import.meta.env.DEV ? '/api' : ''

export default function BatchScanProgress({ batchId, onComplete, onBack, onBackgroundMode }) {
  const [cancelling, setCancelling] = useState(false)
  const { startBackgroundScan, progressData, progressErrors } = useContext(BackgroundScansContext)
  const { addNotification } = useContext(NotificationsContext)
  const hasFiredComplete = useRef(false)

  useEffect(() => {
    if (batchId) startBackgroundScan(batchId)
  }, [batchId, startBackgroundScan])

  const progress = progressData[batchId]
  const error = progressErrors[batchId]

  useEffect(() => {
    if (progress?.status === 'completed' && !hasFiredComplete.current) {
      hasFiredComplete.current = true
      if (onComplete) onComplete(batchId)
    }
  }, [progress?.status, batchId, onComplete])

  const handleGoToBackground = () => {
    startBackgroundScan(batchId)
    if (onBackgroundMode) onBackgroundMode(batchId)
  }

  const handleStopScan = async () => {
    if (!window.confirm('Stop this batch scan? Subdomains still pending or running will be marked as cancelled.')) {
      return
    }
    setCancelling(true)
    try {
      const token = localStorage.getItem('recon_token')
      await fetch(`${API_BASE}/scan/batch-cancel/${batchId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      addNotification(`Batch Scan #${batchId} stopped by user`, 'error')
    } catch (err) {
      console.error('Failed to cancel batch scan:', err)
    } finally {
      setCancelling(false)
      if (onBack) onBack()
    }
  }

  if (!progress) {
    if (error) {
      return (
        <div className="natural-card p-8 text-center space-y-4">
          <div className="flex justify-center">
            <AlertCircle className="w-10 h-10 text-red-500" />
          </div>
          <div>
            <p className="text-slate-900 font-bold">Couldn't load batch scan progress</p>
            <p className="text-slate-600 text-sm mt-1">{error}</p>
          </div>
          {onBack && (
            <button
              onClick={onBack}
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg text-sm font-bold transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Main
            </button>
          )}
        </div>
      )
    }
    return (
      <div className="natural-card p-8 text-center">
        <div className="flex justify-center mb-4">
          <Activity className="w-8 h-8 text-teal-600 animate-spin" />
        </div>
        <p className="text-slate-600">Initializing batch scan...</p>
      </div>
    )
  }

  const progressPercent = progress.progress_percent || 0
  const statusColors = {
    pending: 'bg-slate-200',
    running: 'bg-blue-200',
    completed: 'bg-green-100',
    failed: 'bg-red-100',
    cancelled: 'bg-amber-100'
  }

  const statusTextColors = {
    pending: 'text-slate-700',
    running: 'text-blue-700',
    completed: 'text-green-700',
    failed: 'text-red-700',
    cancelled: 'text-amber-700'
  }

  const statusDots = {
    pending: 'bg-slate-500',
    running: 'bg-blue-500 animate-pulse',
    completed: 'bg-green-500',
    failed: 'bg-red-500',
    cancelled: 'bg-amber-500'
  }

  return (
    <div className="natural-card p-6 space-y-5 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 flex items-center gap-2">
            <Activity className="w-6 h-6 text-teal-600" />
            Batch Subdomain Scan in Progress
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            Scanning {progress.total} unique subdomains with rate limiting
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`px-4 py-2 rounded-lg font-medium ${statusColors[progress.status] || 'bg-slate-200'} ${statusTextColors[progress.status] || 'text-slate-700'}`}>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${statusDots[progress.status] || 'bg-slate-500'}`}></span>
              {progress.status.charAt(0).toUpperCase() + progress.status.slice(1)}
            </div>
          </div>
          {onBackgroundMode && (
            <button
              onClick={handleGoToBackground}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
              title="Move scan to background (continues running, view via widget)"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Background
            </button>
          )}
          {onBack && (
            <button
              onClick={onBack}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
              title="Go back to main dashboard"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Exit
            </button>
          )}
          {progress.status === 'running' || progress.status === 'pending' ? (
            <button
              onClick={handleStopScan}
              disabled={cancelling}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-red-50 hover:bg-red-100 disabled:opacity-50 text-red-700 border border-red-200 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors"
              title="Stop the scan completely (cannot resume)"
            >
              <XCircle className="w-3.5 h-3.5" />
              {cancelling ? 'Stopping...' : 'Stop Scan'}
            </button>
          ) : null}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-slate-700">Overall Progress</span>
          <span className="text-sm font-bold text-teal-600">{progressPercent}%</span>
        </div>
        <div className="w-full bg-slate-200 rounded-full h-3 overflow-hidden">
          <div
            className="bg-gradient-to-r from-teal-500 to-teal-600 h-full rounded-full transition-all duration-500"
            style={{ width: `${progressPercent}%` }}
          ></div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg p-4 border border-blue-200">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-blue-600" />
            <span className="text-xs font-medium text-blue-700">Running</span>
          </div>
          <p className="text-3xl font-bold text-blue-900">
            {progress.status_breakdown?.running || 0}
          </p>
        </div>

        <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-lg p-4 border border-green-200">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="w-4 h-4 text-green-600" />
            <span className="text-xs font-medium text-green-700">Completed</span>
          </div>
          <p className="text-3xl font-bold text-green-900">{progress.completed}</p>
        </div>

        <div className="bg-gradient-to-br from-slate-50 to-slate-100 rounded-lg p-4 border border-slate-200">
          <div className="flex items-center gap-2 mb-2">
            <Clock className="w-4 h-4 text-slate-600" />
            <span className="text-xs font-medium text-slate-700">Pending</span>
          </div>
          <p className="text-3xl font-bold text-slate-900">
            {progress.status_breakdown?.pending || 0}
          </p>
        </div>

        <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-4 border border-red-200">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="w-4 h-4 text-red-600" />
            <span className="text-xs font-medium text-red-700">Failed</span>
          </div>
          <p className="text-3xl font-bold text-red-900">{progress.failed}</p>
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="font-semibold text-slate-900 text-sm">Subdomain Status</h3>
        <div className="bg-slate-50 rounded-lg h-96 overflow-y-auto border border-slate-200">
          {progress.subdomains?.map((sub, idx) => (
            <div
              key={idx}
              className="px-5 py-4 border-b border-slate-200 last:border-0 flex items-center justify-between hover:bg-slate-100 transition-colors"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span
                  className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                    sub.status === 'completed'
                      ? 'bg-green-500'
                      : sub.status === 'running'
                      ? 'bg-blue-500 animate-pulse'
                      : sub.status === 'failed'
                      ? 'bg-red-500'
                      : sub.status === 'cancelled'
                      ? 'bg-amber-500'
                      : 'bg-slate-400'
                  }`}
                ></span>
                <span className="text-sm font-medium text-slate-800 truncate">
                  {sub.subdomain}
                </span>
              </div>
              <span className="text-xs font-medium text-slate-600 flex-shrink-0 ml-2">
                {sub.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {progress.status === 'completed' && (
        <div className="bg-gradient-to-r from-green-50 to-emerald-50 border border-green-300 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-6 h-6 text-green-600" />
            <div>
              <h3 className="font-bold text-green-900">Batch Scan Completed</h3>
              <p className="text-sm text-green-800">All subdomains have been scanned successfully</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="text-center">
              <p className="text-2xl font-bold text-green-700">{progress.completed}</p>
              <p className="text-xs text-green-600">Completed</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-red-700">{progress.failed}</p>
              <p className="text-xs text-red-600">Failed</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-slate-700">{progress.total}</p>
              <p className="text-xs text-slate-600">Total</p>
            </div>
          </div>
          <button
            onClick={() => (onComplete ? onComplete(batchId) : onBack && onBack())}
            className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-bold transition-colors"
          >
            View Batch Results
          </button>
        </div>
      )}
    </div>
  )
}
