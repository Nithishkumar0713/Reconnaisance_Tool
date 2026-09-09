import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

export default function Section({ title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="border border-ink-700 rounded-md mb-3 bg-ink-900/40">
      
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-5 py-3 text-left hover:bg-ink-800/50 transition"
      >
        {open ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        <span className="mono text-xs uppercase tracking-widest text-slate-300">{title}</span>
      </button>

      {open && (
        <div className="px-5 pb-5 pt-2 border-t border-ink-700">
          {children}
        </div>
      )}
    </div>
  )
}

