import { useState } from 'react'
import {
  Zap,
  Search,
  Shield,
  ShieldCheck,
  Play,
  Globe,
  FileText,
  Lock,
  MapPin,
  FileCode,
  Layers,
  AlertTriangle,
  Bug,
  Server,
  GitBranch,
  FolderOpen,
  RefreshCw,
  Cloud,
  ShieldAlert,
  Fingerprint,
  ArrowRight,
  Mail,
  KeyRound,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
  Info,
  CheckCircle2,
  Radar,
  Wifi,
  Users,
  Sliders
} from 'lucide-react'

import { MAX_FULL_SCAN_BATCH_TARGETS, parseTargetList, countRawExpandedTargets } from '../utils/batchTargets'

const CAPABILITIES = [
  {
    key: 'dns_records',
    icon: Globe,
    title: 'DNS Records',
    desc: 'Queries zone records including A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA.',
    color: 'bg-blue-50 text-blue-600 border-blue-100',
    cardStyle: 'border-t-4 border-t-blue-500 hover:border-blue-500/70',
  },
  {
    key: 'whois',
    icon: FileText,
    title: 'WHOIS Registry',
    desc: 'Retrieves domain registration dates, registrar, host nameservers, and organization.',
    color: 'bg-slate-100 text-slate-600 border-slate-200',
    cardStyle: 'border-t-4 border-t-slate-500 hover:border-slate-500/70',
  },
  {
    key: 'ssl_certificate',
    icon: Lock,
    title: 'SSL/TLS Certificate',
    desc: 'Validates SSL chains, issuer authority, expiration limits, and SAN hostnames.',
    color: 'bg-teal-50 text-teal-600 border-teal-100',
    cardStyle: 'border-t-4 border-t-teal-500 hover:border-teal-500/70',
  },
  {
    key: 'geo_ip',
    icon: MapPin,
    title: 'GeoIP Location',
    desc: 'Maps server country, city, ISP name, ASN registries, and proxy/hosting network flags.',
    color: 'bg-rose-50 text-rose-600 border-rose-100',
    cardStyle: 'border-t-4 border-t-red-500 hover:border-red-500/70',
  },
  {
    key: 'http_headers',
    icon: FileCode,
    title: 'HTTP Headers',
    desc: 'Checks response headers, redirect chain traces, and active HTTP cookies.',
    color: 'bg-cyan-50 text-cyan-600 border-cyan-100',
    cardStyle: 'border-t-4 border-t-cyan-500 hover:border-cyan-500/70',
  },
  {
    key: 'web_technologies',
    icon: Layers,
    title: 'Web Technologies',
    desc: 'Identifies backend CMS, frontend frameworks, JS libraries, CDN, and analytics engines.',
    color: 'bg-amber-50 text-amber-600 border-amber-100',
    cardStyle: 'border-t-4 border-t-amber-500 hover:border-amber-500/70',
  },
  {
    key: 'abuseipdb',
    icon: AlertTriangle,
    title: 'AbuseIPDB Reputation',
    desc: 'Checks IP reputation history, abuse confidence rating %, and spam report counts.',
    color: 'bg-orange-50 text-orange-600 border-orange-100',
    cardStyle: 'border-t-4 border-t-orange-500 hover:border-orange-500/70',
  },
  {
    key: 'virustotal',
    icon: Bug,
    title: 'VirusTotal Threat Intel',
    desc: 'Queries malicious/suspicious detection stats across antivirus search engines.',
    color: 'bg-rose-50 text-rose-600 border-rose-100',
    cardStyle: 'border-t-4 border-t-rose-500 hover:border-rose-500/70',
  },
  {
    key: 'port_scan',
    icon: Server,
    title: 'Active Ports & Services',
    desc: 'Probes TCP ports with firewall checks and service banners across custom ranges up to 1-65535.',
    color: 'bg-indigo-50 text-indigo-600 border-indigo-100',
    cardStyle: 'border-t-4 border-t-indigo-500 hover:border-indigo-500/70',
  },
  {
    key: 'subdomains',
    icon: GitBranch,
    title: 'Subdomain Index',
    desc: 'Discovers active subdomains using passive certificate transparency indexes and brute-force lists.',
    color: 'bg-purple-50 text-purple-605 text-purple-600 border-purple-200',
    cardStyle: 'border-t-4 border-t-purple-500 hover:border-purple-500/70',
  },
  {
    key: 'directories',
    icon: FolderOpen,
    title: 'Directory Enumeration',
    desc: 'Runs brute-force checks against target paths to discover hidden directories and routes.',
    color: 'bg-teal-50 text-teal-605 text-teal-600 border-teal-100',
    cardStyle: 'border-t-4 border-t-emerald-500 hover:border-emerald-500/70',
  },
  {
    key: 'reverse_dns',
    icon: RefreshCw,
    title: 'Reverse DNS PTR',
    desc: 'Executes reverse pointer lookups mapping host IP addresses back to domain names.',
    color: 'bg-violet-50 text-violet-750 text-violet-700 border-violet-200',
    cardStyle: 'border-t-4 border-t-violet-500 hover:border-violet-500/70',
  },
  {
    key: 'cloud_provider',
    icon: Cloud,
    title: 'Cloud Provider',
    desc: 'Identifies if the target is hosted on AWS, GCP, Azure, Cloudflare, or other cloud platforms.',
    color: 'bg-sky-50 text-sky-600 border-sky-100',
    cardStyle: 'border-t-4 border-t-sky-500 hover:border-sky-500/70',
  },
  {
    key: 'waf_detect',
    icon: ShieldAlert,
    title: 'WAF Detection',
    desc: 'Detects Web Application Firewalls by sending crafted probes and analyzing block responses.',
    color: 'bg-red-50 text-red-600 border-red-100',
    cardStyle: 'border-t-4 border-t-red-500 hover:border-red-500/70',
  },
  {
    key: 'cms_fingerprint',
    icon: Fingerprint,
    title: 'CMS Fingerprinting',
    desc: 'Detects WordPress, Joomla, Drupal, Shopify, and 10+ other CMS platforms with version info.',
    color: 'bg-fuchsia-50 text-fuchsia-600 border-fuchsia-100',
    cardStyle: 'border-t-4 border-t-fuchsia-500 hover:border-fuchsia-500/70',
  },
  {
    key: 'http_availability',
    icon: Wifi,
    title: 'HTTP/HTTPS Accessibility',
    desc: 'Independently tests port 80 and 443 reachability — status code, HTTP version, and whether HTTP properly redirects to HTTPS.',
    color: 'bg-lime-50 text-lime-700 border-lime-200',
    cardStyle: 'border-t-4 border-t-lime-500 hover:border-lime-500/70',
  },
  {
    key: 'email_gather',
    icon: Mail,
    title: 'Email Harvesting',
    desc: 'Discovers domain-associated email addresses using 15+ concurrent OSINT sources, PGP registries, and DNS records.',
    color: 'bg-violet-50 text-violet-600 border-violet-100',
    cardStyle: 'border-t-4 border-t-violet-500 hover:border-violet-500/70',
  },
  {
    key: 'shodan_intel',
    icon: Radar,
    title: 'Shodan Intel',
    desc: "Cross-references indexed ports, software versions, and known CVEs from Shodan's own internet-wide scan data.",
    color: 'bg-indigo-50 text-indigo-600 border-indigo-100',
    cardStyle: 'border-t-4 border-t-indigo-500 hover:border-indigo-500/70',
  }
]

export default function ScanForm({ onSubmit, onSubmitBatch, onSelectModule }) {
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState('fast')
  const [includeReputation, setIncludeReputation] = useState(false)

  const [targetMode, setTargetMode] = useState('single')
  const [batchRaw, setBatchRaw] = useState('')
  const [batchIncludeReputation, setBatchIncludeReputation] = useState(true)
  const [batchMaxConcurrent, setBatchMaxConcurrent] = useState(null)
  const [batchError, setBatchError] = useState('')

  const [abuseipdbKey, setAbuseipdbKey] = useState(() => {
    try { return localStorage.getItem('recon_abuseipdb_key') || '' } catch { return '' }
  })
  const [virustotalKey, setVirustotalKey] = useState(() => {
    try { return localStorage.getItem('recon_virustotal_key') || '' } catch { return '' }
  })
  const [showApiKeys, setShowApiKeys] = useState(false)
  const [showKeyPassword, setShowKeyPassword] = useState(false)

  const [verifyingAbuse, setVerifyingAbuse] = useState(false)
  const [verifyingVt, setVerifyingVt] = useState(false)
  const [abuseStatus, setAbuseStatus] = useState(null)
  const [vtStatus, setVtStatus] = useState(null)

  const handleAbuseipdbChange = (val) => {
    setAbuseipdbKey(val)
    setAbuseStatus(null)
    try { localStorage.setItem('recon_abuseipdb_key', val) } catch {}
  }

  const handleVirustotalChange = (val) => {
    setVirustotalKey(val)
    setVtStatus(null)
    try { localStorage.setItem('recon_virustotal_key', val) } catch {}
  }

  const verifyKey = async (service, keyVal) => {
    const keyToTest = (keyVal || '').trim()
    if (!keyToTest) return

    if (service === 'abuseipdb') {
      setVerifyingAbuse(true)
      setAbuseStatus(null)
    } else {
      setVerifyingVt(true)
      setVtStatus(null)
    }

    try {
      const token = localStorage.getItem('recon_token')
      const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'
      const response = await fetch(`${API_BASE}/verify-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ service, api_key: keyToTest })
      })

      const data = await response.json()
      if (service === 'abuseipdb') {
        setAbuseStatus({ valid: data.valid, message: data.message })
      } else {
        setVtStatus({ valid: data.valid, message: data.message })
      }
    } catch (err) {
      const errRes = { valid: false, message: 'Connection error during key verification.' }
      if (service === 'abuseipdb') setAbuseStatus(errRes)
      else setVtStatus(errRes)
    } finally {
      if (service === 'abuseipdb') setVerifyingAbuse(false)
      else setVerifyingVt(false)
    }
  }

  const isValidTarget = target.trim().length > 0;

  // Deep mode: 3 concurrent targets, ~70-90s each observed in practice
  // (port scan + directory enum + subdomain enum + email gather all run
  // per target). Standard mode: 6 concurrent, all-passive, ~15-20s each.
  // VirusTotal's own ~16s-per-request pacing applies across the *whole*
  // batch regardless of target concurrency, so it's checked as a floor.
  let batchTargetCount = 0
  let batchEtaSeconds = null
  try {
    batchTargetCount = countRawExpandedTargets(batchRaw, MAX_FULL_SCAN_BATCH_TARGETS)
    if (batchTargetCount > 0) {
      const concurrency = batchMaxConcurrent || (mode === 'deep' ? 3 : 6)
      const perTargetSeconds = mode === 'deep' ? 80 : 18
      const waves = Math.ceil(batchTargetCount / concurrency)
      let eta = waves * perTargetSeconds
      if (mode === 'deep' && batchIncludeReputation) {
        eta = Math.max(eta, batchTargetCount * 16)
      }
      batchEtaSeconds = eta
    }
  } catch {
    // handled by batchError below via parseTargetList on submit
  }

  const formatEta = (seconds) => {
    if (seconds < 60) return `~${Math.round(seconds)}s`
    const m = Math.floor(seconds / 60)
    const s = Math.round(seconds % 60)
    return `~${m}m${s > 0 ? ` ${s}s` : ''}`
  }

  const handleSubmit = (e) => {
    e.preventDefault()

    let finalAbuseKey = abuseipdbKey.trim()
    let finalVtKey = virustotalKey.trim()
    if (!finalAbuseKey) {
      try { finalAbuseKey = (localStorage.getItem('recon_abuseipdb_key') || '').trim() } catch {}
    }
    if (!finalVtKey) {
      try { finalVtKey = (localStorage.getItem('recon_virustotal_key') || '').trim() } catch {}
    }

    if (targetMode === 'batch') {
      setBatchError('')
      let targets
      try {
        targets = parseTargetList(batchRaw, MAX_FULL_SCAN_BATCH_TARGETS)
      } catch (err) {
        setBatchError(err.message)
        return
      }
      if (targets.length === 0) {
        setBatchError('Enter at least one target.')
        return
      }
      if (targets.length > MAX_FULL_SCAN_BATCH_TARGETS) {
        setBatchError(`Too many targets (${targets.length}). Maximum is ${MAX_FULL_SCAN_BATCH_TARGETS} per batch.`)
        return
      }
      if (!onSubmitBatch) return
      onSubmitBatch({
        targets,
        mode,
        includeReputation: batchIncludeReputation,
        maxConcurrent: batchMaxConcurrent,
        abuseipdbApiKey: finalAbuseKey || null,
        virustotalApiKey: finalVtKey || null
      })
      return
    }

    if (!isValidTarget) return
    onSubmit({
      target: target.trim(),
      mode,
      includeReputation: true,
      abuseipdbApiKey: finalAbuseKey || null,
      virustotalApiKey: finalVtKey || null
    })
  }

  return (
    <div className="w-full max-w-[1600px] mx-auto pt-6 animate-fade-in delay-1">
      <div className="mb-12 text-center max-w-3xl mx-auto">
        <h1 className="text-5xl font-black tracking-tight text-slate-900 leading-none">
          Reconnaissance Tool
        </h1>
        <p className="mt-5 text-sm text-natural-muted leading-relaxed max-w-lg mx-auto font-bold">
          Enter a domain or IP address (e.g., google.com or 1.1.1.1) to analyze server configuration, security headers, and network details.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="max-w-2xl mx-auto space-y-6">
        {onSubmitBatch && (
          <div className="flex items-center gap-2 justify-center">
            <button
              type="button"
              onClick={() => setTargetMode('single')}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all ${
                targetMode === 'single' ? 'bg-teal-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              Single Target
            </button>
            <button
              type="button"
              onClick={() => setTargetMode('batch')}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all ${
                targetMode === 'batch' ? 'bg-teal-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Users className="w-3.5 h-3.5" />
              Batch, up to {MAX_FULL_SCAN_BATCH_TARGETS}
            </button>
          </div>
        )}

        {targetMode === 'single' ? (
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-slate-400" />
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter domain or IP (e.g., google.com or 1.1.1.1)"
              className="w-full pl-12 pr-4 py-4 bg-white border border-slate-250 rounded-2xl text-slate-900 placeholder-slate-400 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/10 transition-all duration-200 text-sm shadow-sm font-normal"
              autoFocus
            />
          </div>
        ) : (
          <div className="space-y-2.5">
            <textarea
              value={batchRaw}
              onChange={(e) => { setBatchRaw(e.target.value); setBatchError('') }}
              placeholder="Up to 20 domains/IPs — comma-separated, or a range like 110.0.0.1-20"
              rows={4}
              className="w-full px-4 py-3.5 bg-white border border-slate-250 rounded-2xl text-slate-900 placeholder-slate-400 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/10 transition-all duration-200 text-sm shadow-sm font-normal resize-none"
              autoFocus
            />
            {batchError && (
              <p className="text-xs text-red-600 font-semibold">{batchError}</p>
            )}
            {!batchError && batchTargetCount > 0 && (
              <p className="text-xs text-slate-500 font-semibold">
                {batchTargetCount} target{batchTargetCount === 1 ? '' : 's'}
                {batchTargetCount > MAX_FULL_SCAN_BATCH_TARGETS ? ` — maximum is ${MAX_FULL_SCAN_BATCH_TARGETS}` : ''}
                {batchEtaSeconds != null && batchTargetCount <= MAX_FULL_SCAN_BATCH_TARGETS && (
                  <> — est. {formatEta(batchEtaSeconds)}{mode === 'deep' && batchIncludeReputation ? ' (VirusTotal allows ~4 checks/min)' : ''}</>
                )}
              </p>
            )}

            <div className="flex items-center justify-between flex-wrap gap-3 pt-1">
              <label className="flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={batchIncludeReputation}
                  onChange={(e) => setBatchIncludeReputation(e.target.checked)}
                  className="rounded border-slate-300 text-teal-600 focus:ring-teal-500"
                />
                Include reputation checks (VirusTotal/AbuseIPDB) — adds ~16s/target in Deep mode
              </label>

              <label className="flex items-center gap-2 text-xs font-semibold text-slate-700">
                <Sliders className="w-3.5 h-3.5 text-slate-400" />
                Concurrent scans:
                <input
                  type="range"
                  min={1}
                  max={mode === 'deep' ? 5 : 8}
                  value={batchMaxConcurrent || (mode === 'deep' ? 3 : 6)}
                  onChange={(e) => setBatchMaxConcurrent(Number(e.target.value))}
                  className="w-24 accent-teal-600"
                />
                <span className="mono text-teal-700 font-bold w-4 text-center">{batchMaxConcurrent || (mode === 'deep' ? 3 : 6)}</span>
              </label>
            </div>
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-4">
          <button
            type="button"
            onClick={() => {
              setMode('fast')
              setShowApiKeys(false)
            }}
            className={`text-left p-5 rounded-2xl border transition-all duration-255 relative ${
              mode === 'fast'
                ? 'border-teal-500 bg-white shadow-md glow-sage'
                : 'border-slate-200 bg-white/60 hover:border-slate-300'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <Zap className={`w-4 h-4 ${mode === 'fast' ? 'text-teal-600 font-bold' : 'text-slate-400'}`} />
              <span className="text-sm font-bold text-slate-800 uppercase tracking-wider">Standard Check</span>
              <span className="text-xs text-natural-muted ml-auto mono font-bold">~45s</span>
            </div>
            <p className="text-xs text-natural-muted leading-relaxed">
              Checks DNS records, SSL setups, web technologies, and gathers domain intelligence.
            </p>
          </button>

          <button
            type="button"
            onClick={() => {
              setMode('deep')
              setShowApiKeys(true)
            }}
            className={`text-left p-5 rounded-2xl border transition-all duration-255 relative ${
              mode === 'deep'
                ? 'border-teal-500 bg-white shadow-md glow-sage'
                : 'border-slate-200 bg-white/60 hover:border-slate-300'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <Search className={`w-4 h-4 ${mode === 'deep' ? 'text-teal-600 font-bold' : 'text-slate-400'}`} />
              <span className="text-sm font-bold text-slate-800 uppercase tracking-wider">Deep Check</span>
              <span className="text-xs text-natural-muted ml-auto mono font-bold">~2m</span>
            </div>
            <p className="text-xs text-natural-muted leading-relaxed">
              Standard check plus port scanning, directory enumeration, reverse DNS, subdomain enumeration, cloud provider detection, and threat reputation lookups.
            </p>
          </button>
        </div>

        <div className="border border-slate-200 bg-white/80 rounded-2xl overflow-hidden transition-all duration-300 shadow-sm">
          <button
            type="button"
            onClick={() => setShowApiKeys(!showApiKeys)}
            className="w-full px-5 py-3.5 flex items-center justify-between bg-slate-50/60 hover:bg-slate-100/60 text-left transition duration-150 cursor-pointer select-none"
          >
            <div className="flex items-center gap-2.5">
              <KeyRound className="w-4 h-4 text-teal-600" />
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                API Keys (Optional for Threat Intel & Reputation)
              </span>
              {(abuseipdbKey || virustotalKey) && (
                <span className="text-[10px] bg-teal-100 text-teal-800 px-2 py-0.5 rounded-full font-bold">
                  Keys Configured
                </span>
              )}
            </div>
            {showApiKeys ? (
              <ChevronUp className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            )}
          </button>

          {showApiKeys && (
            <div className="p-5 border-t border-slate-150 space-y-4 bg-white animate-fade-in">
              <p className="text-xs text-slate-500 leading-relaxed font-medium flex items-center gap-1.5">
                <Info className="w-4 h-4 text-teal-600 flex-shrink-0" />
                <span>Provide API keys to unlock AbuseIPDB threat reputation and VirusTotal antivirus scanner engines. Keys are saved locally in your browser.</span>
              </p>

              <div className="space-y-4">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                    <span>AbuseIPDB API Key</span>
                    <div className="flex items-center gap-2 normal-case">
                      <button
                        type="button"
                        onClick={() => verifyKey('abuseipdb', abuseipdbKey)}
                        disabled={!abuseipdbKey.trim() || verifyingAbuse}
                        className="text-teal-700 hover:text-teal-900 font-bold text-[10px] bg-teal-50 hover:bg-teal-100 border border-teal-200 px-2.5 py-0.5 rounded-lg transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {verifyingAbuse ? 'Verifying...' : 'Verify Key'}
                      </button>
                      <span className="text-slate-300">|</span>
                      <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer" className="text-teal-600 hover:underline font-semibold text-[10px]">Get Key →</a>
                    </div>
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type={showKeyPassword ? 'text' : 'password'}
                      value={abuseipdbKey}
                      onChange={(e) => handleAbuseipdbChange(e.target.value)}
                      placeholder="Enter AbuseIPDB API key..."
                      className={`w-full pl-9 pr-8 py-2.5 bg-slate-50 border rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white transition ${
                        abuseStatus ? (abuseStatus.valid ? 'border-emerald-500 ring-2 ring-emerald-500/10' : 'border-red-400 ring-2 ring-red-500/10') : 'border-slate-200 focus:border-teal-500'
                      }`}
                    />
                  </div>
                  {abuseStatus && (
                    <div className={`mt-1.5 text-[11px] font-semibold flex items-center gap-1.5 ${abuseStatus.valid ? 'text-emerald-700' : 'text-red-600'}`}>
                      {abuseStatus.valid ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <AlertTriangle className="w-3.5 h-3.5 text-red-500" />}
                      <span>{abuseStatus.message}</span>
                    </div>
                  )}
                </div>

                <div>
                  <label className="text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                    <span>VirusTotal API Key</span>
                    <div className="flex items-center gap-2 normal-case">
                      <button
                        type="button"
                        onClick={() => verifyKey('virustotal', virustotalKey)}
                        disabled={!virustotalKey.trim() || verifyingVt}
                        className="text-teal-700 hover:text-teal-900 font-bold text-[10px] bg-teal-50 hover:bg-teal-100 border border-teal-200 px-2.5 py-0.5 rounded-lg transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {verifyingVt ? 'Verifying...' : 'Verify Key'}
                      </button>
                      <span className="text-slate-300">|</span>
                      <a href="https://www.virustotal.com/gui/my-api-key" target="_blank" rel="noreferrer" className="text-teal-600 hover:underline font-semibold text-[10px]">Get Key →</a>
                    </div>
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type={showKeyPassword ? 'text' : 'password'}
                      value={virustotalKey}
                      onChange={(e) => handleVirustotalChange(e.target.value)}
                      placeholder="Enter VirusTotal API key..."
                      className={`w-full pl-9 pr-8 py-2.5 bg-slate-50 border rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white transition ${
                        vtStatus ? (vtStatus.valid ? 'border-emerald-500 ring-2 ring-emerald-500/10' : 'border-red-400 ring-2 ring-red-500/10') : 'border-slate-200 focus:border-teal-500'
                      }`}
                    />
                  </div>
                  {vtStatus && (
                    <div className={`mt-1.5 text-[11px] font-semibold flex items-center gap-1.5 ${vtStatus.valid ? 'text-emerald-700' : 'text-red-600'}`}>
                      {vtStatus.valid ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <AlertTriangle className="w-3.5 h-3.5 text-red-500" />}
                      <span>{vtStatus.message}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={() => setShowKeyPassword(!showKeyPassword)}
                  className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center gap-1 font-semibold cursor-pointer"
                >
                  {showKeyPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  <span>{showKeyPassword ? 'Hide Key Characters' : 'Show Key Characters'}</span>
                </button>
                {(abuseipdbKey || virustotalKey) && (
                  <button
                    type="button"
                    onClick={() => {
                      handleAbuseipdbChange('')
                      handleVirustotalChange('')
                    }}
                    className="text-[11px] text-red-500 hover:text-red-700 font-semibold cursor-pointer"
                  >
                    Clear Keys
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={targetMode === 'batch' ? (batchTargetCount === 0 || batchTargetCount > MAX_FULL_SCAN_BATCH_TARGETS) : !isValidTarget}
          className="w-full flex items-center justify-center gap-2 py-4 bg-teal-600 hover:bg-teal-700 text-white font-bold uppercase tracking-widest rounded-2xl disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 glow-sage shadow-md hover:shadow-lg"
        >
          <Play className="w-4.5 h-4.5" fill="currentColor" />
          {targetMode === 'batch' ? 'Start Batch Diagnostics' : 'Start Diagnostics'}
        </button>
      </form>

      <div className="my-16 border-t border-slate-200/60 max-w-lg mx-auto" />

      <div className="space-y-6 w-full">
        <div className="text-center">
          <h2 className="text-sm font-extrabold uppercase tracking-widest text-slate-900">Included Checks</h2>
          <p className="text-[11px] text-slate-500 mt-1.5 font-bold">The diagnostics check will analyze the following parameters of the host:</p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-5 w-full">
          {CAPABILITIES.map((cap, i) => {
            const Icon = cap.icon
            return (
              <div
                key={i}
                onClick={() => onSelectModule && onSelectModule(cap.key)}
                className={`natural-card bg-white p-5 rounded-2xl flex flex-col justify-between hover:-translate-y-1 hover:shadow-md transition-all duration-350 select-none group border-slate-200 cursor-pointer h-full ${cap.cardStyle}`}
              >
                <div>
                  <div className={`w-9 h-9 rounded-xl border flex items-center justify-center mb-4 transition-all duration-300 group-hover:scale-105 ${cap.color}`}>
                    <Icon className="w-4.5 h-4.5" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 group-hover:text-teal-700 transition duration-200">{cap.title}</h3>
                  <p className="text-xs text-slate-605 text-slate-600 mt-2.5 leading-relaxed font-semibold">
                    {cap.desc}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

