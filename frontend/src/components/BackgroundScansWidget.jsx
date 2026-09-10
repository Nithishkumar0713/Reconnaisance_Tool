import { useContext } from 'react'
import { BackgroundScansContext } from '../BackgroundScansContext'
import { Activity, ChevronUp, ChevronDown, X } from 'lucide-react'

export default function BackgroundScansWidget({ onScanClick }) {
  const { backgroundScans, expandedScanId, toggleExpandScan, progressData: progress } = useContext(BackgroundScansContext)
  const scanCount = Object.keys(backgroundScans).length

  if (scanCount === 0) {
    return null
  }

  const isExpanded = expandedScanId !== null
  const status = progress[expandedScanId]?.status
  const isCompleted = status === 'completed'
  const isStopped = status === 'cancelled' || status === 'failed'
  const headerColorClass = isCompleted
    ? 'bg-gradient-to-r from-green-500 to-green-600'
    : isStopped
      ? 'bg-gradient-to-r from-amber-500 to-amber-600'
      : 'bg-gradient-to-r from-teal-500 to-teal-600'
  const statusLabel = isCompleted
    ? 'Completed!'
    : status === 'cancelled'
      ? 'Cancelled'
      : status === 'failed'
        ? 'Failed'
        : 'Running in background'
  const buttonLabel = isCompleted ? 'View Results' : isStopped ? 'View Details' : 'View Full Progress'
  const buttonColorClass = isCompleted
    ? 'bg-green-500 hover:bg-green-600'
    : isStopped
      ? 'bg-amber-500 hover:bg-amber-600'
      : 'bg-teal-500 hover:bg-teal-600'

  return (
    <div className="fixed bottom-6 right-6 z-40">
      {!isExpanded && (
        <button
          onClick={() => toggleExpandScan(Object.keys(backgroundScans)[0])}
          className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-teal-500 to-teal-600 text-white rounded-full shadow-lg hover:shadow-xl transition-all hover:scale-105"
          title="Click to view background scan progress"
        >
          <Activity className="w-5 h-5 animate-spin" />
          <span className="font-semibold">{scanCount} Scan{scanCount !== 1 ? 's' : ''} Running</span>
        </button>
      )}

      {isExpanded && expandedScanId && (
        <div className="bg-white rounded-lg shadow-2xl border border-slate-200 w-80 max-h-96 flex flex-col overflow-hidden">
          <div className={`text-white p-4 flex items-center justify-between ${headerColorClass}`}>
            <div className="flex items-center gap-2">
              {isCompleted ? (
                <span className="w-5 h-5 text-green-100">✓</span>
              ) : isStopped ? (
                <X className="w-5 h-5" />
              ) : (
                <Activity className="w-5 h-5 animate-spin" />
              )}
              <div>
                <h3 className="font-semibold text-sm">Batch Scan Progress</h3>
                <p className="text-xs opacity-75">{statusLabel}</p>
              </div>
            </div>
            <button
              onClick={() => toggleExpandScan(expandedScanId)}
              className="p-1 hover:bg-teal-400 rounded transition-colors"
              title="Minimize"
            >
              <ChevronDown className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {progress[expandedScanId] && (
              <>
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="font-medium text-slate-700">Progress</span>
                    <span className="font-bold text-teal-600">{progress[expandedScanId].progress_percent || 0}%</span>
                  </div>
                  <div className="w-full bg-slate-200 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-teal-500 to-teal-600 h-full rounded-full transition-all duration-500"
                      style={{ width: `${progress[expandedScanId].progress_percent || 0}%` }}
                    ></div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-blue-50 rounded p-2 border border-blue-200">
                    <p className="text-blue-700 font-medium">Running</p>
                    <p className="text-lg font-bold text-blue-900">{progress[expandedScanId].status_breakdown?.running || 0}</p>
                  </div>
                  <div className="bg-green-50 rounded p-2 border border-green-200">
                    <p className="text-green-700 font-medium">Completed</p>
                    <p className="text-lg font-bold text-green-900">{progress[expandedScanId].completed || 0}</p>
                  </div>
                  <div className="bg-slate-50 rounded p-2 border border-slate-200">
                    <p className="text-slate-700 font-medium">Pending</p>
                    <p className="text-lg font-bold text-slate-900">{progress[expandedScanId].status_breakdown?.pending || 0}</p>
                  </div>
                  <div className="bg-red-50 rounded p-2 border border-red-200">
                    <p className="text-red-700 font-medium">Failed</p>
                    <p className="text-lg font-bold text-red-900">{progress[expandedScanId].failed || 0}</p>
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="bg-slate-50 border-t border-slate-200 p-3 flex gap-2">
            <button
              onClick={() => onScanClick(expandedScanId)}
              className={`flex-1 px-3 py-2 text-white rounded text-xs font-bold transition-colors ${buttonColorClass}`}
            >
              {buttonLabel}
            </button>
            <button
              onClick={() => toggleExpandScan(expandedScanId)}
              className="px-3 py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 rounded text-xs font-bold transition-colors"
              title="Minimize to badge"
            >
              <ChevronUp className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
