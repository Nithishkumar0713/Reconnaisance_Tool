import { History, ArrowUpRight, Clock, Shield, X, CheckCircle2, Zap, AlertTriangle } from 'lucide-react'

export default function ScanHistoryModal({ history = [], onClose, onViewScan, isScanActive = false }) {
  const safeHistory = Array.isArray(history) ? history : []

  const formatDate = (isoString) => {
    if (!isoString) return 'Recent'
    try {
      let str = String(isoString)
      if (!str.endsWith('Z') && !str.includes('+') && !str.includes('-')) {
        str += 'Z'
      }
      const d = new Date(str)
      if (isNaN(d.getTime())) return String(isoString)
      return d.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      })
    } catch {
      return String(isoString)
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-fade-in">
      <div 
        className="w-full max-w-2xl bg-white rounded-3xl shadow-2xl border border-slate-100 overflow-hidden transform transition-all flex flex-col max-h-[85vh] animate-scale-up"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 px-6 py-5 text-white flex items-center justify-between relative flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/20 border border-white/40 flex items-center justify-center text-white">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-black tracking-tight text-white leading-tight">
                Scan History
              </h2>
              <p className="text-xs text-orange-100 font-medium">
                {safeHistory.length} {safeHistory.length === 1 ? 'record' : 'records'} logged for your account
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-white transition cursor-pointer"
              aria-label="Close modal"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-6 overflow-y-auto flex-1 space-y-3">
          {isScanActive && (
            <div className="flex items-start gap-3 p-4 bg-amber-50 border border-amber-200 rounded-2xl">
              <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-bold text-amber-900">A scan is currently running</p>
                <p className="text-xs text-amber-700 mt-0.5 leading-relaxed">
                  Viewing a result below would replace your active scan. Finish it, or move a batch scan to background, before opening history results.
                </p>
              </div>
            </div>
          )}

          {safeHistory.length === 0 ? (
            <div className="py-12 text-center flex flex-col items-center justify-center">
              <div className="w-16 h-16 rounded-full bg-orange-100/70 border border-orange-200 flex items-center justify-center text-orange-500 mb-3">
                <History className="w-8 h-8" />
              </div>
              <h3 className="text-sm font-bold text-slate-800">No Scan History Found</h3>
              <p className="text-xs text-slate-500 max-w-xs mt-1 leading-relaxed">
                You haven't executed any target host diagnostics scans yet. Run a standard or deep check to populate your log.
              </p>
            </div>
          ) : (
            safeHistory.map((item) => (
              <div
                key={item.id}
                className="group p-4 bg-slate-50 hover:bg-orange-50/40 border border-slate-200 hover:border-orange-300/80 rounded-2xl transition-all duration-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm"
              >
                <div className="space-y-1 flex-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-sm font-extrabold text-slate-900 font-mono tracking-tight">
                      {item.target}
                    </span>
                    {item.batch ? (
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-teal-100 text-teal-800 border border-teal-200 flex items-center gap-1">
                        <Zap className="w-3 h-3" />
                        Batch Scan
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-orange-100 text-orange-800 border border-orange-200">
                        {item.module ? item.module : item.mode || 'Standard'}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <span>{formatDate(item.timestamp)}</span>
                    </div>
                    {item.data?.summary && (
                      <div className="flex items-center gap-1 text-emerald-600 font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Analysis Saved</span>
                      </div>
                    )}
                    {item.batch && (
                      <div className="flex items-center gap-1 text-teal-600 font-semibold">
                        <span>{item.batch.completed_scans || 0}/{item.batch.total_subdomains || 0} completed</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  {item.batch ? (
                    <button
                      onClick={() => !isScanActive && onViewScan({...item, isBatchScan: true})}
                      disabled={isScanActive}
                      className={`px-3 py-1.5 rounded-xl text-white text-xs font-bold flex items-center gap-1.5 transition shadow-sm ${
                        isScanActive ? 'bg-slate-300 cursor-not-allowed' : 'bg-teal-500 hover:bg-teal-600 cursor-pointer'
                      }`}
                      title={isScanActive ? 'Locked while a scan is running' : 'View batch scan results'}
                    >
                      <span>View Batch Results</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  ) : item.data ? (
                    <button
                      onClick={() => !isScanActive && onViewScan(item)}
                      disabled={isScanActive}
                      className={`px-3 py-1.5 rounded-xl text-white text-xs font-bold flex items-center gap-1.5 transition shadow-sm ${
                        isScanActive ? 'bg-slate-300 cursor-not-allowed' : 'bg-orange-500 hover:bg-orange-600 cursor-pointer'
                      }`}
                      title={isScanActive ? 'Locked while a scan is running' : undefined}
                    >
                      <span>View Results</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  ) : null}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="bg-slate-50 px-6 py-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 flex-shrink-0">
          <div className="flex items-center gap-1.5 font-medium">
            <Shield className="w-4 h-4 text-orange-500" />
            <span>Audit logs securely recorded in database</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-200 hover:bg-slate-300 text-slate-800 rounded-xl font-bold transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
