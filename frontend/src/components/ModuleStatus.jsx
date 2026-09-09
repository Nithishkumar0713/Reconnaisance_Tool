import { AlertTriangle, Clock, Ban, CheckCircle2, MinusCircle, WifiOff, ShieldAlert, KeyRound, Zap } from 'lucide-react'

export function ModuleStatus({ data, moduleName = '' }) {
  if (!data) return null

  const status = data.status
  if (status === 'ok' || status === undefined) return null

  const iconFor = (code) => {
    if (code === 'timeout') return <Clock className="w-4 h-4" />
    if (code === 'firewall_filtered') return <ShieldAlert className="w-4 h-4" />
    if (code === 'connection_refused') return <Ban className="w-4 h-4" />
    if (code === 'api_key_missing') return <KeyRound className="w-4 h-4" />
    if (code === 'api_rate_limited') return <Zap className="w-4 h-4" />
    if (code === 'api_unreachable') return <WifiOff className="w-4 h-4" />
    if (code === 'unauthorized') return <KeyRound className="w-4 h-4" />
    if (code === 'not_found') return <MinusCircle className="w-4 h-4" />
    return <AlertTriangle className="w-4 h-4" />
  }

  const colorFor = (s) => {
    if (s === 'skipped' || s === 'not_found' || s === 'no_records' || s === 'no_ptr') {
      return 'text-slate-600 border-slate-200 bg-slate-50'
    }
    if (s === 'partial') {
      return 'text-amber-600 border-amber-200 bg-amber-50'
    }
    return 'text-red-600 border-red-200 bg-red-50'
  }

  const label = (s) => {
    const map = {
      skipped: 'Skipped',
      error: 'Failed',
      partial: 'Partial data',
      not_found: 'Not found',
      no_records: 'No records',
      nxdomain: 'Domain does not exist',
      no_nameservers: 'No nameservers responded',
      no_ptr: 'No PTR record',
      rate_limited: 'Rate limited',
      unavailable: 'Unavailable',
      timeout: 'Timed out',
    }
    return map[s] || s
  }

  const code = data.error_code
  const message = data.error_message || data.reason || data.note
  const httpStatus = data.http_status

  return (
    <div className={`border rounded-md p-4 mono text-sm ${colorFor(status)}`}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex-shrink-0">{iconFor(code || status)}</div>
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="uppercase tracking-widest text-[10px] font-semibold">
              {label(status)}
            </span>
            {code && (
              <span className="text-[10px] px-1.5 py-0.5 border border-current rounded opacity-70">
                {code}
              </span>
            )}
            {httpStatus && (
              <span className="text-[10px] px-1.5 py-0.5 border border-current rounded opacity-70">
                HTTP {httpStatus}
              </span>
            )}
          </div>
          
          {message && (
            <div className="mt-1.5 text-slate-600 text-xs leading-relaxed">{message}</div>
          )}

          {data.attempts && Array.isArray(data.attempts) && data.attempts.length > 0 && (
            <div className="mt-2 text-[10px] text-slate-500 space-y-0.5">
              {data.attempts.map((a, i) => (
                <div key={i}>
                  <span className="opacity-60">tried:</span> {a.url} — {a.failure}
                  {a.detail && ` (${a.detail})`}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function StatusBadge({ status }) {
  if (status === 'ok') {
    return (
      <span className="mono text-[10px] uppercase tracking-widest text-emerald-600 flex items-center gap-1">
        <CheckCircle2 className="w-3 h-3" /> ok
      </span>
    )
  }
  if (status === 'skipped') {
    return (
      <span className="mono text-[10px] uppercase tracking-widest text-slate-500 flex items-center gap-1">
        <MinusCircle className="w-3 h-3" /> skipped
      </span>
    )
  }
  if (status === 'partial') {
    return (
      <span className="mono text-[10px] uppercase tracking-widest text-amber-600 flex items-center gap-1">
        <AlertTriangle className="w-3 h-3" /> partial
      </span>
    )
  }
  return (
    <span className="mono text-[10px] uppercase tracking-widest text-red-500 flex items-center gap-1">
      <Ban className="w-3 h-3" /> error
    </span>
  )
}
