import { User, Mail, ShieldCheck, Hash, X, KeyRound, Clock } from 'lucide-react'
import { useState, useEffect } from 'react'

export default function AccountModal({ user, onClose }) {
  if (!user) return null

  const getInitials = (name) => {
    if (!name || typeof name !== 'string') return 'U'
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .substring(0, 2)
  }

  const API_BASE = import.meta.env.DEV ? '/api' : ''
  const [loginHistory, setLoginHistory] = useState([])

  useEffect(() => {
    const fetchHistory = async () => {
      const token = localStorage.getItem('recon_token')
      if (!token) return
      try {
        const res = await fetch(`${API_BASE}/history/logins`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
        if (res.ok) {
          const data = await res.json()
          if (Array.isArray(data) && data.length > 0) {
            setLoginHistory(data)
          } else {
            setLoginHistory([{ timestamp: new Date().toISOString(), session_type: 'Current Web Session' }])
          }
        }
      } catch (err) {
        console.error('Failed to fetch login history from DB:', err)
        setLoginHistory([{ timestamp: new Date().toISOString(), session_type: 'Current Web Session' }])
      }
    }
    fetchHistory()
  }, [])

  const safeLoginHistory = Array.isArray(loginHistory) ? loginHistory : []

  const formatDate = (isoString) => {
    if (!isoString) return 'Active Session'
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
        second: '2-digit',
        hour12: true
      })
    } catch {
      return String(isoString)
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-slate-900/60 backdrop-blur-md animate-fade-in">
      <div 
        className="w-full max-w-2xl bg-white rounded-3xl shadow-2xl border border-slate-100 overflow-hidden transform transition-all animate-scale-up max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 px-8 py-7 text-white relative flex-shrink-0 shadow-sm">
          <button
            onClick={onClose}
            className="absolute top-5 right-5 w-9 h-9 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-white transition cursor-pointer active:scale-95"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-5">
            <div className="w-20 h-20 rounded-2xl bg-white/20 border-2 border-white/40 flex items-center justify-center text-white text-3xl font-black shadow-inner flex-shrink-0">
              {getInitials(user.name || user.full_name)}
            </div>
            <div>
              <h2 className="text-2xl font-black tracking-tight text-white leading-snug">
                {user.name || user.full_name || 'Authenticated User'}
              </h2>
              <div className="flex items-center gap-2 mt-1 text-orange-100 text-xs font-semibold">
                <ShieldCheck className="w-4 h-4 text-orange-200" />
                <span>Verified Account</span>
              </div>
            </div>
          </div>
        </div>

        <div className="p-8 space-y-6 overflow-y-auto flex-1 bg-slate-50/50">
          <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-xs space-y-4">
            <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-400 pb-1 border-b border-slate-100">
              Account Credentials & Security
            </h3>

            <div className="flex items-center justify-between pb-3.5 border-b border-slate-100">
              <div className="flex items-center gap-3 text-xs text-slate-500 font-semibold">
                <User className="w-4.5 h-4.5 text-orange-500" />
                <span>Full Name</span>
              </div>
              <span className="text-sm font-extrabold text-slate-800">
                {user.name || user.full_name || 'N/A'}
              </span>
            </div>

            <div className="flex items-center justify-between pb-3.5 border-b border-slate-100">
              <div className="flex items-center gap-3 text-xs text-slate-500 font-semibold">
                <Mail className="w-4.5 h-4.5 text-orange-500" />
                <span>Email Address</span>
              </div>
              <span className="text-sm font-extrabold text-slate-800 font-mono">
                {user.email || 'N/A'}
              </span>
            </div>

            <div className="flex items-center justify-between pb-3.5 border-b border-slate-100">
              <div className="flex items-center gap-3 text-xs text-slate-500 font-semibold">
                <Hash className="w-4.5 h-4.5 text-orange-500" />
                <span>Account ID</span>
              </div>
              <span className="text-sm font-extrabold text-slate-800 font-mono">
                #{user.id || '101'}
              </span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-3 text-xs text-slate-500 font-semibold">
                <KeyRound className="w-4.5 h-4.5 text-orange-500" />
                <span>Auth Session</span>
              </div>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-200">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                JWT Active
              </span>
            </div>
          </div>

          <div className="bg-orange-50/80 border border-orange-200/80 rounded-2xl p-4.5 flex items-start gap-4 shadow-xs">
            <ShieldCheck className="w-6 h-6 text-orange-600 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-orange-950 font-medium leading-relaxed">
              You are securely logged into the Reconnaissance Host Diagnostics platform. Your authorization token is active for current session requests.
            </p>
          </div>

          <div className="bg-white border border-slate-200/80 rounded-2xl p-6 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2.5 text-sm font-black text-slate-800">
                <Clock className="w-4.5 h-4.5 text-orange-500" />
                <span>Account Login History</span>
              </div>
              <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-orange-100 text-orange-800 border border-orange-200">
                {safeLoginHistory.length} {safeLoginHistory.length === 1 ? 'entry' : 'entries'}
              </span>
            </div>

            <div className="space-y-2.5 max-h-48 overflow-y-auto pr-1">
              {safeLoginHistory.map((item, idx) => (
                <div key={idx} className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50/60 border border-slate-200/70 shadow-2xs hover:border-orange-300 transition-all">
                  <div className="flex items-center gap-3">
                    <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${idx === 0 ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
                    <div>
                      <div className="text-xs font-extrabold text-slate-800 font-mono tracking-tight">
                        {formatDate(item.timestamp)}
                      </div>
                      <div className="text-[11px] font-semibold text-slate-500 mt-0.5">
                        {idx === 0 ? 'Current Active Session' : (item.session_type || item.type || 'Web Access')}
                      </div>
                    </div>
                  </div>
                  <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                    idx === 0
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                      : 'bg-slate-100 text-slate-600 border border-slate-200'
                  }`}>
                    {idx === 0 ? 'Active' : 'Logged'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-white px-8 py-5 border-t border-slate-100 flex justify-end flex-shrink-0 shadow-inner">
          <button
            onClick={onClose}
            className="px-7 py-2.5 bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 text-white rounded-xl text-xs font-extrabold tracking-wide transition shadow-md hover:shadow-lg cursor-pointer active:scale-95"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  )
}


