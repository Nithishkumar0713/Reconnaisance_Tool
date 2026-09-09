import { useEffect, useState } from 'react'
import { Activity, Cpu } from 'lucide-react'

const BASE_STAGES = [
  { key: 'headers', label: 'Inspecting HTTP response headers and cookies', at: 2 },
  { key: 'tech', label: 'Analyzing web application frontend technologies', at: 3 },
  { key: 'http_availability', label: 'Testing HTTP/HTTPS port reachability', at: 4 },
  { key: 'shodan_intel', label: 'Querying Shodan InternetDB for open ports and CVEs', at: 5 },
  { key: 'waf', label: 'Fingerprinting WAF and bot-protection layers', at: 6 },
  { key: 'cms', label: 'Detecting CMS platform signatures', at: 7 },
  { key: 'whois', label: 'Retrieving Registrar registration data', at: 9 },
  { key: 'ssl', label: 'Validating SSL/TLS Certificate authenticity', at: 12 },
  { key: 'geo', label: 'Locating server IP address and ASN', at: 16 },
  { key: 'dns', label: 'Resolving DNS Nameservers and Zone records', at: 45 },
]

const DEEP_STAGES = [
  { key: 'cloud', label: 'Identifying cloud hosting provider', at: 32 },
  { key: 'subs', label: 'Querying passive subdomain providers', at: 50 },
  { key: 'ports', label: 'Probing TCP socket ports and banners', at: 70 },
  { key: 'directories', label: 'Brute-forcing common directory paths', at: 88 },
  { key: 'reverse_dns', label: 'Performing reverse DNS PTR lookup', at: 98 },
  { key: 'email_gather', label: 'Harvesting public domain email addresses', at: 108 },
  { key: 'reputation', label: 'Checking IP reputation across threat feeds', at: 114 },
]

export default function ScanProgress({ startTime, mode }) {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed(((Date.now() - startTime) / 1000))
    }, 100)
    return () => clearInterval(interval)
  }, [startTime])

  const STAGES = mode === 'deep' ? [...BASE_STAGES, ...DEEP_STAGES] : BASE_STAGES

  const activeStageIndex = STAGES.findIndex(s => elapsed <= s.at)
  const currentStage = activeStageIndex !== -1 ? STAGES[activeStageIndex] : STAGES[STAGES.length - 1]

  return (
    <div className="max-w-xl mx-auto pt-8 animate-fade-in">
      <div className="border border-natural-border bg-white rounded-2xl p-8 glow-sage relative overflow-hidden shadow-sm">
        
        <div className="flex items-center justify-between border-b border-natural-border pb-4 mb-6">
          <div className="flex items-center gap-1.5">
            <span className="mono text-[10px] text-stone-400 uppercase tracking-widest font-bold">Analysis Log</span>
          </div>
          <div className="flex items-center gap-1 text-[11px] text-emerald-650 text-emerald-600 font-semibold mono tracking-wider animate-pulse">
            <Activity className="w-3.5 h-3.5" />
            RUNNING
          </div>
        </div>

        <div className="text-center my-6">
          <div className="mono text-5xl font-extrabold text-stone-900 tracking-tight tabular-nums flex items-baseline justify-center">
            {elapsed.toFixed(1)}
            <span className="text-xl text-stone-400 font-normal ml-1">s</span>
          </div>
          <div className="mono text-[10px] text-stone-400 uppercase tracking-wider mt-2 flex items-center justify-center gap-1.5 font-medium">
            <Cpu className="w-3 h-3 text-stone-450" /> Running async checks
          </div>
        </div>

        {currentStage && (
          <div className="bg-stone-50 border border-stone-200 rounded-xl p-3 mb-6 text-center">
            <div className="mono text-[9px] text-stone-400 uppercase tracking-wider font-semibold">Active Request</div>
            <div className="text-xs text-emerald-700 mt-1 font-mono font-medium truncate">
              {currentStage.label}...
            </div>
          </div>
        )}

        <div className="space-y-2 mt-4 max-h-72 overflow-y-auto pr-1">
          {STAGES.map((stage, i) => {
            const isDone = elapsed > stage.at
            const prevAt = i > 0 ? STAGES[i - 1].at : 0
            const isActive = !isDone && elapsed > prevAt
            return (
              <div
                key={stage.key}
                className={`flex items-center justify-between border px-4 py-2.5 rounded-xl transition-all duration-300 mono text-xs ${
                  isDone
                    ? 'border-emerald-250 bg-emerald-50/10 text-emerald-700/85'
                    : isActive
                      ? 'border-emerald-400 bg-emerald-50/30 text-emerald-800 font-medium glow-sage'
                      : 'border-stone-100 bg-transparent text-stone-400'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-1.5 h-1.5 rounded-full ${
                    isDone ? 'bg-emerald-500' : isActive ? 'bg-emerald-500 animate-ping' : 'bg-stone-200'
                  }`} />
                  <span>{stage.label}</span>
                </div>
                <span className="text-[9px] uppercase tracking-widest font-bold">
                  {isDone ? 'done' : isActive ? 'running' : 'queued'}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
