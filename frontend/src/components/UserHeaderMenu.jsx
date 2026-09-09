import { useState, useRef, useEffect } from 'react'
import { User, History, LogOut, ChevronDown, ShieldCheck } from 'lucide-react'

export default function UserHeaderMenu({ user, onOpenAccount, onOpenHistory, onLogout, isScanActive = false }) {
  const [isOpen, setIsOpen] = useState(false)
  const menuRef = useRef(null)

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const displayName = user?.name || user?.full_name || (user?.email ? user.email.split('@')[0] : 'My Account')
  const initial = displayName.charAt(0).toUpperCase()

  return (
    <div className="relative inline-block text-left" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-orange-700/40 hover:bg-orange-700/70 border border-orange-400/40 text-white transition-all duration-200 cursor-pointer shadow-sm active:scale-95 group"
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <div className="w-6 h-6 rounded-full bg-white/20 border border-white/40 flex items-center justify-center text-[11px] font-black text-white uppercase shadow-inner flex-shrink-0">
          {initial}
        </div>
        
        <span className="text-xs font-bold tracking-wide max-w-[130px] sm:max-w-[170px] truncate text-orange-50 group-hover:text-white">
          {displayName}
        </span>

        <ChevronDown className={`w-3.5 h-3.5 text-orange-200 transition-transform duration-200 ${isOpen ? 'rotate-180 text-white' : ''}`} />
      </button>

      {isOpen && (
        <div className="fixed z-[60] bg-white rounded-lg shadow-2xl border border-slate-200 overflow-hidden animate-fade-in" style={{ width: '320px', top: '72px', right: '16px' }}>
          <div className="bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 text-white p-4">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-orange-100">Signed in as</p>
            <p className="text-sm font-bold truncate mt-1">{user?.email || displayName}</p>
          </div>

          <div className="divide-y divide-slate-200">
            <button
              onClick={() => {
                setIsOpen(false)
                onOpenAccount()
              }}
              className="w-full flex items-center gap-3 px-4 py-4 text-sm font-bold text-slate-700 hover:bg-orange-50 transition cursor-pointer group"
            >
              <div className="w-5 h-5 rounded flex items-center justify-center text-orange-600 group-hover:text-orange-700 transition">
                <User className="w-5 h-5" />
              </div>
              <span>My Account</span>
            </button>

            <button
              onClick={() => {
                if (isScanActive) return
                setIsOpen(false)
                onOpenHistory()
              }}
              disabled={isScanActive}
              title={isScanActive ? 'Locked while a scan is running' : undefined}
              className={`w-full flex items-center gap-3 px-4 py-4 text-sm font-bold transition group ${
                isScanActive
                  ? 'text-slate-300 cursor-not-allowed'
                  : 'text-slate-700 hover:bg-orange-50 cursor-pointer'
              }`}
            >
              <div className={`w-5 h-5 rounded flex items-center justify-center transition ${
                isScanActive ? 'text-slate-300' : 'text-orange-600 group-hover:text-orange-700'
              }`}>
                <History className="w-5 h-5" />
              </div>
              <span>Scan History{isScanActive ? ' (locked)' : ''}</span>
            </button>

            <button
              onClick={() => {
                if (isScanActive) return
                setIsOpen(false)
                onLogout()
              }}
              disabled={isScanActive}
              title={isScanActive ? 'Locked while a scan is running' : undefined}
              className={`w-full flex items-center gap-3 px-4 py-4 text-sm font-bold transition group ${
                isScanActive
                  ? 'text-slate-300 cursor-not-allowed'
                  : 'text-red-600 hover:bg-red-50 cursor-pointer'
              }`}
            >
              <div className={`w-5 h-5 rounded flex items-center justify-center transition ${
                isScanActive ? 'text-slate-300' : 'text-red-600 group-hover:text-red-700'
              }`}>
                <LogOut className="w-5 h-5" />
              </div>
              <span>Logout{isScanActive ? ' (locked)' : ''}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
