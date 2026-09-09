import { useState, useEffect, useRef } from 'react'
import {
  Download,
  RotateCcw,
  Copy,
  Check,
  ShieldAlert,
  Globe,
  Wifi,
  Radar,
  Server,
  Key,
  ShieldCheck,
  ArrowLeft,
  ArrowRight,
  Database,
  Layers,
  FileText,
  MapPin,
  ListFilter,
  Activity,
  Search,
  LayoutDashboard,
  Fingerprint,
  Cloud,
  Shield,
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  SlidersHorizontal,
  Mail,
  RefreshCw,
  Zap,
  AlertTriangle,
  Lock,
  Unlock,
  HelpCircle
} from 'lucide-react'
import { ModuleStatus } from './ModuleStatus'
import { SCAN_REPORT_STYLES, buildScanReportBody, buildScanReportBodyTwoPane } from '../utils/scanReportHtml'

const HEADER_DESCRIPTIONS = {
  'strict-transport-security': 'Enforces HTTPS connections exclusively across the domain and subdomains. Prevents protocol downgrade attacks, SSL stripping, and cookie interception.',
  'Strict-Transport-Security': 'Enforces HTTPS connections exclusively across the domain and subdomains. Prevents protocol downgrade attacks, SSL stripping, and cookie interception.',
  'content-security-policy': 'Restricts authorized script, frame, and media sources allowed to execute on the page. Serves as the primary defense against Cross-Site Scripting (XSS) and data injection.',
  'Content-Security-Policy': 'Restricts authorized script, frame, and media sources allowed to execute on the page. Serves as the primary defense against Cross-Site Scripting (XSS) and data injection.',
  'content-security-policy-report-only': 'Logs CSP policy violation reports to a designated URI without blocking resource loading. Allows administrators to safely test and refine security policies before enforcement.',
  'Content-Security-Policy-Report-Only': 'Logs CSP policy violation reports to a designated URI without blocking resource loading. Allows administrators to safely test and refine security policies before enforcement.',
  'x-frame-options': 'Specifies whether the document can be embedded within <iframe>, <embed>, or <object> elements. Prevents Clickjacking attacks by blocking unauthorized site framing.',
  'X-Frame-Options': 'Specifies whether the document can be embedded within <iframe>, <embed>, or <object> elements. Prevents Clickjacking attacks by blocking unauthorized site framing.',
  'x-content-type-options': 'Disables browser MIME-sniffing and enforces the declared Content-Type header strictly. Prevents non-executable files like user uploads from being interpreted as scripts.',
  'X-Content-Type-Options': 'Disables browser MIME-sniffing and enforces the declared Content-Type header strictly. Prevents non-executable files like user uploads from being interpreted as scripts.',
  'referrer-policy': 'Controls the amount of URL referrer information sent to external sites during navigation. Protects user privacy and prevents sensitive internal path leakage.',
  'Referrer-Policy': 'Controls the amount of URL referrer information sent to external sites during navigation. Protects user privacy and prevents sensitive internal path leakage.',
  'permissions-policy': 'Restricts web application and iframe access to device APIs such as camera, microphone, and geolocation. Prevents unauthorized scripts from silently accessing hardware sensors.',
  'Permissions-Policy': 'Restricts web application and iframe access to device APIs such as camera, microphone, and geolocation. Prevents unauthorized scripts from silently accessing hardware sensors.',
  'x-xss-protection': 'Configures legacy browser audit engines to stop page loading when reflected XSS is detected. Provides fallback protection for older clients when modern CSP is unavailable.',
  'X-XSS-Protection': 'Configures legacy browser audit engines to stop page loading when reflected XSS is detected. Provides fallback protection for older clients when modern CSP is unavailable.',
  'cross-origin-embedder-policy': 'Requires cross-origin resources to explicitly grant load permission via CORS or CORP headers. Enables browser process isolation to defend against Spectre side-channel attacks.',
  'Cross-Origin-Embedder-Policy': 'Requires cross-origin resources to explicitly grant load permission via CORS or CORP headers. Enables browser process isolation to defend against Spectre side-channel attacks.',
  'cross-origin-opener-policy': 'Isolates top-level browsing contexts from cross-origin documents opened via links. Prevents cross-window tabnabbing and protects against side-channel memory leaks.',
  'Cross-Origin-Opener-Policy': 'Isolates top-level browsing contexts from cross-origin documents opened via links. Prevents cross-window tabnabbing and protects against side-channel memory leaks.',
  'cross-origin-resource-policy': 'Restricts static asset and media reading exclusively to trusted origins. Blocks cross-site data theft and unauthorized resource embedding.',
  'Cross-Origin-Resource-Policy': 'Restricts static asset and media reading exclusively to trusted origins. Blocks cross-site data theft and unauthorized resource embedding.',
  'access-control-allow-origin': 'Defines external origin domains authorized to access resource data via cross-site HTTP requests. Enforces strict origin boundaries to prevent unauthorized API data exposure.',
  'Access-Control-Allow-Origin': 'Defines external origin domains authorized to access resource data via cross-site HTTP requests. Enforces strict origin boundaries to prevent unauthorized API data exposure.'
}

export const HEADER_IDEAL_CONFIGS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';",
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';",
  'content-security-policy-report-only': "default-src 'self'; report-uri /csp-violation-report-endpoint/",
  'Content-Security-Policy-Report-Only': "default-src 'self'; report-uri /csp-violation-report-endpoint/",
  'x-frame-options': 'DENY (or SAMEORIGIN if framing is required)',
  'X-Frame-Options': 'DENY (or SAMEORIGIN if framing is required)',
  'x-content-type-options': 'nosniff',
  'X-Content-Type-Options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin (or no-referrer)',
  'Referrer-Policy': 'strict-origin-when-cross-origin (or no-referrer)',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'x-xss-protection': '0 (OWASP Recommended if CSP active) or 1; mode=block',
  'X-XSS-Protection': '0 (OWASP Recommended if CSP active) or 1; mode=block',
  'cross-origin-embedder-policy': 'require-corp',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'access-control-allow-origin': 'Explicit trusted origin (e.g. https://yourdomain.com). Avoid wildcard (*)',
  'Access-Control-Allow-Origin': 'Explicit trusted origin (e.g. https://yourdomain.com). Avoid wildcard (*)'
}

export function getHeaderMisconfigWarning(name, val) {
  if (!name || !val) return null
  const lname = String(name).toLowerCase()
  const sval = String(val).toLowerCase()

  if (lname === 'strict-transport-security') {
    if (sval.includes('max-age=0')) {
      return { severity: 'CRITICAL', text: 'MISCONFIGURATION: max-age=0 explicitly disables HTTPS enforcement (HSTS).' }
    }
    if (!sval.includes('includesubdomains')) {
      return { severity: 'WARN', text: 'SUB-OPTIMAL: Missing "includeSubDomains" directive, subdomains remain vulnerable to HTTP downgrade.' }
    }
  }
  if (lname === 'x-xss-protection') {
    if (sval === '0') {
      return { severity: 'WARN', text: 'CONFIG AUDIT: Set to "0" (Disabled). Recommended setting is "0" only if a robust CSP is present, otherwise "1; mode=block".' }
    }
  }
  if (lname === 'x-frame-options') {
    if (sval.includes('allow-from *') || sval === 'allowall') {
      return { severity: 'CRITICAL', text: 'MISCONFIGURATION: Permissive framing allowed. Page remains vulnerable to Clickjacking.' }
    }
  }
  if (lname === 'access-control-allow-origin') {
    if (sval === '*') {
      return { severity: 'WARN', text: 'CORS PERMISSIVE: Wildcard (*) allows any external domain to read sensitive response data.' }
    }
  }
  if (lname === 'content-security-policy') {
    if (sval.includes('unsafe-inline') || sval.includes('unsafe-eval')) {
      return { severity: 'WARN', text: 'CSP WEAKNESS: Includes "unsafe-inline" or "unsafe-eval", diminishing XSS protection.' }
    }
  }
  return null
}

function ModuleAccordionItem({
  id,
  title,
  subtitle,
  icon: Icon,
  badgeText,
  badgeType = 'default',
  accentColor = 'teal',
  isOpen,
  onToggle,
  children
}) {
  const colorMap = {
    blue: {
      border: 'border-l-4 border-l-blue-500',
      activeBorder: 'border-blue-300 ring-2 ring-blue-500/10',
      iconBg: 'bg-blue-50 text-blue-600 border-blue-150',
      badge: 'bg-blue-50 text-blue-700 border-blue-200'
    },
    indigo: {
      border: 'border-l-4 border-l-indigo-500',
      activeBorder: 'border-indigo-300 ring-2 ring-indigo-500/10',
      iconBg: 'bg-indigo-50 text-indigo-600 border-indigo-150',
      badge: 'bg-indigo-50 text-indigo-700 border-indigo-200'
    },
    slate: {
      border: 'border-l-4 border-l-slate-500',
      activeBorder: 'border-slate-300 ring-2 ring-slate-500/10',
      iconBg: 'bg-slate-100 text-slate-700 border-slate-200',
      badge: 'bg-slate-100 text-slate-700 border-slate-200'
    },
    purple: {
      border: 'border-l-4 border-l-purple-500',
      activeBorder: 'border-purple-300 ring-2 ring-purple-500/10',
      iconBg: 'bg-purple-50 text-purple-600 border-purple-150',
      badge: 'bg-purple-50 text-purple-700 border-purple-200'
    },
    teal: {
      border: 'border-l-4 border-l-teal-500',
      activeBorder: 'border-teal-300 ring-2 ring-teal-500/10',
      iconBg: 'bg-teal-50 text-teal-600 border-teal-150',
      badge: 'bg-teal-50 text-teal-700 border-teal-200'
    },
    amber: {
      border: 'border-l-4 border-l-amber-500',
      activeBorder: 'border-amber-300 ring-2 ring-amber-500/10',
      iconBg: 'bg-amber-50 text-amber-600 border-amber-150',
      badge: 'bg-amber-50 text-amber-700 border-amber-200'
    },
    cyan: {
      border: 'border-l-4 border-l-cyan-500',
      activeBorder: 'border-cyan-300 ring-2 ring-cyan-500/10',
      iconBg: 'bg-cyan-50 text-cyan-600 border-cyan-150',
      badge: 'bg-cyan-50 text-cyan-700 border-cyan-200'
    },
    emerald: {
      border: 'border-l-4 border-l-emerald-500',
      activeBorder: 'border-emerald-300 ring-2 ring-emerald-500/10',
      iconBg: 'bg-emerald-50 text-emerald-600 border-emerald-150',
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200'
    },
    sky: {
      border: 'border-l-4 border-l-sky-500',
      activeBorder: 'border-sky-300 ring-2 ring-sky-500/10',
      iconBg: 'bg-sky-50 text-sky-600 border-sky-150',
      badge: 'bg-sky-50 text-sky-700 border-sky-200'
    },
    red: {
      border: 'border-l-4 border-l-red-500',
      activeBorder: 'border-red-300 ring-2 ring-red-500/10',
      iconBg: 'bg-red-50 text-red-600 border-red-150',
      badge: 'bg-red-50 text-red-700 border-red-200'
    },
    fuchsia: {
      border: 'border-l-4 border-l-fuchsia-500',
      activeBorder: 'border-fuchsia-300 ring-2 ring-fuchsia-500/10',
      iconBg: 'bg-fuchsia-50 text-fuchsia-600 border-fuchsia-150',
      badge: 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200'
    },
    lime: {
      border: 'border-l-4 border-l-lime-500',
      activeBorder: 'border-lime-300 ring-2 ring-lime-500/10',
      iconBg: 'bg-lime-50 text-lime-700 border-lime-200',
      badge: 'bg-lime-50 text-lime-800 border-lime-200'
    },
    rose: {
      border: 'border-l-4 border-l-rose-500',
      activeBorder: 'border-rose-300 ring-2 ring-rose-500/10',
      iconBg: 'bg-rose-50 text-rose-600 border-rose-150',
      badge: 'bg-rose-50 text-rose-700 border-rose-200'
    },
    violet: {
      border: 'border-l-4 border-l-violet-500',
      activeBorder: 'border-violet-300 ring-2 ring-violet-500/10',
      iconBg: 'bg-violet-50 text-violet-600 border-violet-150',
      badge: 'bg-violet-50 text-violet-700 border-violet-200'
    }
  }

  const theme = colorMap[accentColor] || colorMap.teal

  return (
    <div
      id={`module-${id}`}
      className={`border border-slate-200 bg-white rounded-2xl shadow-sm hover:shadow-md transition-all duration-200 mb-5 overflow-hidden ${theme.border} ${
        isOpen ? theme.activeBorder : ''
      }`}
    >
      <button
        type="button"
        onClick={onToggle}
        className={`w-full p-4 sm:p-5 flex items-center justify-between gap-3 text-left transition-colors cursor-pointer select-none ${
          isOpen ? 'bg-slate-50/70 border-b border-slate-100' : 'hover:bg-slate-50/50'
        }`}
      >
        <div className="flex items-center gap-3.5 min-w-0">
          <div className={`p-2.5 sm:p-3 rounded-xl border flex-shrink-0 ${theme.iconBg}`}>
            <Icon className="w-4 h-4 sm:w-5 sm:h-5" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm sm:text-base font-bold text-slate-900 tracking-tight flex items-center gap-2 truncate">
              {title}
            </h3>
            {subtitle && (
              <p className="text-[11px] text-slate-500 font-semibold tracking-wide mt-0.5 truncate">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {badgeText && (
            <span
              className={`mono text-[10px] sm:text-[11px] font-bold px-2.5 py-1 rounded-lg border hidden xs:inline-block ${
                badgeType === 'skipped'
                  ? 'bg-slate-100 text-slate-500 border-slate-200'
                  : badgeType === 'error'
                  ? 'bg-rose-50 text-rose-600 border-rose-200'
                  : badgeType === 'success'
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : badgeType === 'warning'
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : theme.badge
              }`}
            >
              {badgeText}
            </span>
          )}

          <div
            className={`p-1.5 rounded-lg border transition-all duration-200 ${
              isOpen
                ? 'bg-slate-200/60 border-slate-300 text-slate-800'
                : 'bg-slate-50 border-slate-200 text-slate-400 group-hover:text-slate-600'
            }`}
          >
            <ChevronDown
              className={`w-4 h-4 sm:w-5 sm:h-5 transition-transform duration-200 ${
                isOpen ? 'rotate-180 text-teal-600' : ''
              }`}
            />
          </div>
        </div>
      </button>

      {isOpen && (
        <div className="p-5 sm:p-7 bg-white animate-fade-in border-t border-slate-100">
          {children}
        </div>
      )}
    </div>
  )
}

export default function Results({ data: rawData, onReset, onReScan, onBatchScan }) {
  const isBatch = Array.isArray(rawData.results) && rawData.batch_size !== undefined
  const [selectedTargetIndex, setSelectedTargetIndex] = useState(0)

  const [activeTab, setActiveTab] = useState('overview')
  const [selectedModule, setSelectedModule] = useState('overview')

  const [subdomainQuery, setSubdomainQuery] = useState('')
  const [subdomainFilter, setSubdomainFilter] = useState('all')
  const [directoryFilter, setDirectoryFilter] = useState('all')

  const data = isBatch ? rawData.results[selectedTargetIndex] : rawData
  const hasActiveError = data && !!data.error
  const r = data?.results || {}
  const summary = data?.module_summary || {}

  const downloadHtmlReport = () => {
    // 'detailed' is the legacy subdomain-batch feature's name for the same
    // thing 'deep' means everywhere else (StartBatchScanModal.jsx defaults
    // to and sends the literal string 'detailed') — the backend already
    // treats these as synonyms throughout (ALLOWED_MODES, scan_config.py),
    // so the frontend's mode checks need to as well, or results from that
    // one entry point silently fall through to a different, older layout.
    const usesTwoPaneReport = data.scan_mode === 'fast' || data.scan_mode === 'deep' || data.scan_mode === 'detailed'
    const reportBody = usesTwoPaneReport ? buildScanReportBodyTwoPane(data) : buildScanReportBody(data)
    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnostic Report: ${data.target}</title>
    <style>${SCAN_REPORT_STYLES}</style>
</head>
<body>
    <div class="container">
        ${reportBody}
    </div>
</body>
</html>`

    const blob = new Blob([htmlContent], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `recon_${data.target}_${Date.now()}.html`
    a.click()
    URL.revokeObjectURL(url)
  }

  const isOk = (mod) => mod && mod.status !== 'error' && mod.status !== 'skipped' && !mod.error_code

  const categoryTabs = [
    { id: 'all', label: 'All Modules', icon: Layers },
    { id: 'network', label: 'Network & Ports', icon: Server },
    { id: 'domain', label: 'Domain & DNS', icon: Globe },
    { id: 'web', label: 'Web & Security', icon: ShieldCheck },
    { id: 'recon', label: 'Advanced Recon', icon: Search },
  ]

  const [activeCategory, setActiveCategory] = useState('all')
  const [openModules, setOpenModules] = useState({
    geo_ip: false,
    port_scan: false,
    reverse_dns: false,
    dns_records: false,
    whois: false,
    subdomains: false,
    ssl_certificate: false,
    web_technologies: false,
    http_headers: false,
    http_availability: false,
    shodan_intel: false,
    directory_enum: false,
    cloud_provider: false,
    waf_detect: false,
    cms_fingerprint: false,
    email_gather: false,
    threats: false,
  })

  const toggleModule = (id) => {
    setOpenModules((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const setAllModulesState = (state) => {
    setOpenModules({
      geo_ip: state,
      port_scan: state,
      reverse_dns: state,
      dns_records: state,
      whois: state,
      subdomains: state,
      ssl_certificate: state,
      web_technologies: state,
      http_headers: state,
      http_availability: state,
      shodan_intel: state,
      directory_enum: state,
      cloud_provider: state,
      waf_detect: state,
      cms_fingerprint: state,
      email_gather: state,
      threats: state,
    })
  }

  if (hasActiveError) {
    return (
      <div className="max-w-5xl mx-auto space-y-8 pb-24 animate-fade-in">
        {onReset && (
          <button
            onClick={onReset}
            className="flex items-center gap-2 px-5 py-3 text-xs font-extrabold uppercase tracking-widest text-slate-700 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 hover:border-slate-300 hover:text-slate-900 shadow-sm hover:shadow transition-all duration-150 cursor-pointer select-none"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
        )}

        {isBatch && (
          <div className="border border-slate-200 bg-white rounded-2xl p-4 shadow-sm flex flex-col gap-3">
            <div className="mono text-[10px] text-slate-400 uppercase tracking-widest font-bold">Select Target Report ({rawData.results.length} targets)</div>
            <div className="flex flex-wrap gap-2">
              {rawData.results.map((result, idx) => {
                const hasError = !!result.error
                const isSelected = selectedTargetIndex === idx
                return (
                  <button
                    key={idx}
                    onClick={() => setSelectedTargetIndex(idx)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all duration-200 border ${
                      isSelected
                        ? 'bg-teal-600 border-teal-600 text-white shadow-sm'
                        : hasError
                          ? 'bg-rose-50 border-rose-200 text-rose-600 hover:bg-rose-100/50'
                          : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    {result.target} {hasError && '(Failed)'}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        <div className="border border-slate-200 bg-white rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm glow-sage">
          <div>
            <div className="mono text-[10px] text-slate-400 uppercase tracking-widest mb-1 font-bold">Diagnostics Panel</div>
            <h2 className="mono text-lg font-bold text-slate-900 tracking-wide truncate max-w-md">{data.target}</h2>
            <div className="mono text-[11px] text-red-600 mt-2 font-bold uppercase tracking-wider">
              Scan Failed
            </div>
          </div>
          <div className="flex items-center gap-2">
            {onReScan && (
              <button
                onClick={onReScan}
                className="flex items-center gap-1.5 px-3.5 py-2.5 bg-indigo-50 border border-indigo-200 text-indigo-700 hover:bg-indigo-100 font-bold uppercase tracking-wider text-[10px] mono rounded-xl transition duration-200 shadow-sm cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5 text-indigo-600" />
                re-scan
              </button>
            )}
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 px-4 py-2.5 bg-teal-600 hover:bg-teal-700 text-white font-bold uppercase tracking-wider text-[10px] rounded-xl transition duration-200 shadow-md hover:shadow-lg cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              new check
            </button>
          </div>
        </div>

        <div className="border border-red-200 bg-white rounded-2xl p-8 text-center shadow-sm">
          <ShieldAlert className="w-12 h-12 text-red-600 mx-auto mb-4" />
          <h3 className="text-sm font-bold text-red-800 uppercase tracking-widest">Target Scan Failed</h3>
          <p className="mt-2 text-xs text-red-600 font-mono">
            {data.error}
          </p>
        </div>
      </div>
    )
  }

  // Same 'detailed' === 'deep' synonym as downloadHtmlReport above — without
  // this, every result reached via the subdomain-batch feature (which sends
  // mode='detailed') renders through the older fallback layout further
  // below instead of this one, even though it's functionally a Deep scan.
  const usesTwoPaneLayout = data.scan_mode === 'fast' || data.scan_mode === 'deep' || data.scan_mode === 'detailed'

  if (usesTwoPaneLayout) {
    const NAV_COLORS = {
      teal:    { iconBg: 'bg-teal-50 text-teal-600 border-teal-150',       active: 'bg-teal-50 text-teal-700 border-teal-200' },
      blue:    { iconBg: 'bg-blue-50 text-blue-600 border-blue-150',       active: 'bg-blue-50 text-blue-700 border-blue-200' },
      slate:   { iconBg: 'bg-slate-100 text-slate-700 border-slate-200',   active: 'bg-slate-100 text-slate-700 border-slate-200' },
      amber:   { iconBg: 'bg-amber-50 text-amber-600 border-amber-150',    active: 'bg-amber-50 text-amber-700 border-amber-200' },
      cyan:    { iconBg: 'bg-cyan-50 text-cyan-600 border-cyan-150',       active: 'bg-cyan-50 text-cyan-700 border-cyan-200' },
      red:     { iconBg: 'bg-red-50 text-red-600 border-red-150',         active: 'bg-red-50 text-red-700 border-red-200' },
      purple:  { iconBg: 'bg-purple-50 text-purple-600 border-purple-150', active: 'bg-purple-50 text-purple-700 border-purple-200' },
      sky:     { iconBg: 'bg-sky-50 text-sky-600 border-sky-150',          active: 'bg-sky-50 text-sky-700 border-sky-200' },
      fuchsia: { iconBg: 'bg-fuchsia-50 text-fuchsia-600 border-fuchsia-150', active: 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200' },
      lime:    { iconBg: 'bg-lime-50 text-lime-700 border-lime-200',       active: 'bg-lime-50 text-lime-800 border-lime-200' },
      indigo:  { iconBg: 'bg-indigo-50 text-indigo-600 border-indigo-150', active: 'bg-indigo-50 text-indigo-700 border-indigo-200' },
      violet:  { iconBg: 'bg-violet-50 text-violet-600 border-violet-150', active: 'bg-violet-50 text-violet-700 border-violet-200' },
      emerald: { iconBg: 'bg-emerald-50 text-emerald-600 border-emerald-150', active: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
      orange:  { iconBg: 'bg-orange-50 text-orange-600 border-orange-150', active: 'bg-orange-50 text-orange-700 border-orange-200' },
      rose:    { iconBg: 'bg-rose-50 text-rose-600 border-rose-150', active: 'bg-rose-50 text-rose-700 border-rose-200' },
    }

    const isDeep = data.scan_mode === 'deep' || data.scan_mode === 'detailed'

    const MODULE_NAV = [
      { key: 'overview', label: 'Overview', icon: LayoutDashboard, color: 'teal' },
      { key: 'dns', label: 'DNS Records', icon: Globe, color: 'blue', domainOnly: true },
      { key: 'whois', label: 'WHOIS Registry', icon: FileText, color: 'slate', domainOnly: true },
      { key: 'ssl', label: 'SSL Certificate', icon: Key, color: 'teal' },
      { key: 'geoip', label: 'GeoIP Location', icon: MapPin, color: 'blue' },
      { key: 'tech', label: 'Web Technologies', icon: Layers, color: 'amber' },
      { key: 'headers', label: 'Security Headers', icon: ShieldCheck, color: 'cyan' },
      { key: 'http_availability', label: 'HTTP Availability', icon: Wifi, color: 'teal' },
      { key: 'shodan_intel', label: 'Shodan Intel', icon: Radar, color: 'indigo' },
      { key: 'waf', label: 'WAF Detection', icon: ShieldAlert, color: 'red' },
      { key: 'ports', label: 'Ports & Services', icon: Server, color: 'indigo', deepOnly: true },
      { key: 'directories', label: 'Directory Enum', icon: ListFilter, color: 'emerald', deepOnly: true },
      { key: 'reverse_dns', label: 'Reverse DNS', icon: Globe, color: 'violet', deepOnly: true },
      { key: 'reputation', label: 'IP Reputation', icon: ShieldAlert, color: 'orange', deepOnly: true },
      { key: 'email_gather', label: 'Email Harvesting', icon: Mail, color: 'rose', deepOnly: true, domainOnly: true },
      { key: 'subdomains', label: 'Subdomains', icon: Database, color: 'purple', deepOnly: true, domainOnly: true },
      { key: 'cloud', label: 'Cloud Provider', icon: Cloud, color: 'sky', deepOnly: true },
      { key: 'cms', label: 'CMS Detection', icon: Fingerprint, color: 'fuchsia' },
    ]

    const activeNavItem = MODULE_NAV.find(m => m.key === selectedModule) || MODULE_NAV[0]

    const getModuleBadge = (key) => {
      switch (key) {
        case 'dns': {
          const c = Object.keys(r.dns_records?.records_by_type || {}).length
          return c > 0 ? String(c) : null
        }
        case 'ssl': {
          const d = r.ssl_certificate?.days_until_expiry
          return d != null ? `${d}d` : null
        }
        case 'tech': {
          const c = Object.values(r.web_technologies?.technologies || {}).flat().length
          return c > 0 ? String(c) : null
        }
        case 'headers': {
          const c = Object.keys(r.http_headers?.security_headers_present || {}).length
          return c > 0 ? String(c) : null
        }
        case 'http_availability': {
          const overall = r.http_availability?.overall
          return overall === 'not_accessible' || overall === 'blocked_by_waf' ? '!' : null
        }
        case 'shodan_intel': {
          const c = r.shodan_intel?.vulns?.length
          return c > 0 ? String(c) : null
        }
        case 'subdomains': {
          const c = r.subdomains?.count
          return c > 0 ? String(c) : null
        }
        case 'waf':
          return r.waf_detect?.waf_detected ? '!' : null
        case 'ports': {
          const c = r.port_scan?.open_port_count
          return c > 0 ? String(c) : null
        }
        case 'directories': {
          const c = r.directories?.paths_found ?? r.directory_enum?.found?.length
          return c > 0 ? String(c) : null
        }
        case 'reputation': {
          const abuseScore = r.abuseipdb?.abuse_confidence_score
          const vtMalicious = r.virustotal?.detection_stats?.malicious
          if (abuseScore > 0 || vtMalicious > 0) return '!'
          return null
        }
        case 'email_gather': {
          const c = r.email_gather?.total_found ?? r.email_gather?.emails?.length
          return c > 0 ? String(c) : null
        }
        default:
          return null
      }
    }

    const sslDays = r.ssl_certificate?.days_until_expiry
    let whoisDays = r.whois?.days_until_expiry
    if (whoisDays == null && r.whois?.expiration_date) {
      try {
        const exp = new Date(r.whois.expiration_date)
        if (!isNaN(exp.getTime())) whoisDays = Math.ceil((exp.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      } catch {}
    }
    const techCount = Object.values(r.web_technologies?.technologies || {}).flat().length
    const headersCount = Object.keys(r.http_headers?.security_headers_present || {}).length
    const subdomainsCount = r.subdomains?.count || 0
    const cloudDetected = r.cloud_provider?.cloud_detected
    const cmsDetected = r.cms_fingerprint?.cms_detected
    const wafDetected = r.waf_detect?.waf_detected
    const httpAvailOverall = r.http_availability?.overall
    const shodanVulnCount = r.shodan_intel?.vulns?.length || 0
    const shodanHasData = r.shodan_intel?.has_data !== false
    const geoCountry = r.geo_ip?.country || r.geo_ip?.country_name
    const geoCity = r.geo_ip?.city
    const geoLocation = geoCity && geoCountry ? `${geoCity}, ${geoCountry}` : geoCountry || geoCity

    const TONE_STYLES = {
      good: 'bg-emerald-50 border-emerald-200 text-emerald-800',
      warning: 'bg-amber-50 border-amber-200 text-amber-800',
      danger: 'bg-red-50 border-red-200 text-red-800',
      neutral: 'bg-slate-50 border-slate-200 text-slate-800',
    }
    const TONE_ICON = {
      good: 'bg-emerald-100 text-emerald-600',
      warning: 'bg-amber-100 text-amber-600',
      danger: 'bg-red-100 text-red-600',
      neutral: 'bg-slate-100 text-slate-500',
    }

    const findings = [
      {
        key: 'ssl',
        icon: Key,
        label: 'SSL Certificate',
        value: sslDays != null ? `${sslDays} days remaining` : 'Not available',
        tone: sslDays == null ? 'neutral' : sslDays < 14 ? 'danger' : sslDays < 30 ? 'warning' : 'good',
      },
      data.is_domain && {
        key: 'whois',
        icon: FileText,
        label: 'Domain Expiry',
        value: whoisDays != null ? `${whoisDays} days remaining` : 'Not available',
        tone: whoisDays == null ? 'neutral' : whoisDays < 30 ? 'danger' : whoisDays < 90 ? 'warning' : 'good',
      },
      {
        key: 'headers',
        icon: ShieldCheck,
        label: 'Security Headers',
        value: `${headersCount} active headers`,
        tone: headersCount >= 5 ? 'good' : headersCount >= 2 ? 'warning' : 'danger',
      },
      {
        key: 'waf',
        icon: ShieldAlert,
        label: 'WAF Protection',
        value: wafDetected ? (r.waf_detect.waf_name || 'WAF Detected') : 'No WAF detected',
        tone: wafDetected ? 'good' : 'neutral',
      },
      {
        key: 'http_availability',
        icon: Wifi,
        label: 'HTTP Availability',
        value: httpAvailOverall === 'https_ok' ? 'HTTPS enforced'
          : httpAvailOverall === 'no_forced_https' ? 'HTTPS not enforced'
          : httpAvailOverall === 'http_only' ? 'HTTP only'
          : httpAvailOverall === 'blocked_by_waf' ? 'Blocked by WAF'
          : httpAvailOverall === 'not_accessible' ? 'Not accessible'
          : 'Not available',
        tone: httpAvailOverall === 'https_ok' ? 'good'
          : httpAvailOverall === 'no_forced_https' ? 'warning'
          : httpAvailOverall === 'not_accessible' || httpAvailOverall === 'blocked_by_waf' ? 'danger'
          : 'neutral',
      },
      {
        key: 'shodan_intel',
        icon: Radar,
        label: 'Shodan Intel',
        value: shodanVulnCount > 0 ? `${shodanVulnCount} known CVEs` : shodanHasData ? 'No known CVEs' : 'Not available',
        tone: shodanVulnCount > 0 ? 'danger' : shodanHasData ? 'good' : 'neutral',
      },
      {
        key: 'geoip',
        icon: MapPin,
        label: 'GeoIP Location',
        value: geoLocation || 'Not available',
        tone: 'neutral',
      },
      {
        key: 'tech',
        icon: Layers,
        label: 'Web Technologies',
        value: techCount > 0 ? `${techCount} identified` : 'None identified',
        tone: 'neutral',
      },
      isDeep && data.is_domain && {
        key: 'subdomains',
        icon: Database,
        label: 'Subdomains',
        value: subdomainsCount > 0 ? `${subdomainsCount} discovered` : 'None found',
        tone: 'neutral',
      },
      isDeep && {
        key: 'cloud',
        icon: Cloud,
        label: 'Cloud Provider',
        value: cloudDetected ? r.cloud_provider.provider : 'Self-hosted / non-cloud',
        tone: 'neutral',
      },
      {
        key: 'cms',
        icon: Fingerprint,
        label: 'CMS Platform',
        value: cmsDetected ? r.cms_fingerprint.cms_name : 'No known CMS',
        tone: 'neutral',
      },
      isDeep && data.is_domain && {
        key: 'email_gather',
        icon: Mail,
        label: 'Email Harvesting',
        value: (r.email_gather?.total_found ?? r.email_gather?.emails?.length) > 0 ? `${r.email_gather?.total_found ?? r.email_gather?.emails?.length} discovered` : 'None found',
        tone: 'neutral',
      },
      isDeep && {
        key: 'ports',
        icon: Server,
        label: 'Open Ports',
        value: r.port_scan?.open_port_count > 0 ? `${r.port_scan.open_port_count} open` : 'None found',
        tone: r.port_scan?.open_port_count > 0 ? 'warning' : 'good',
      },
      isDeep && {
        key: 'directories',
        icon: ListFilter,
        label: 'Directory Enum',
        value: (r.directories?.paths_found ?? r.directory_enum?.found?.length) > 0 ? `${r.directories?.paths_found ?? r.directory_enum?.found?.length} discovered` : 'None found',
        tone: 'neutral',
      },
      isDeep && {
        key: 'reputation',
        icon: ShieldAlert,
        label: 'IP Reputation',
        value: (r.abuseipdb?.abuse_confidence_score > 0 || r.virustotal?.detection_stats?.malicious > 0) ? 'Flagged by threat intel' : 'Clean',
        tone: (r.abuseipdb?.abuse_confidence_score > 0 || r.virustotal?.detection_stats?.malicious > 0) ? 'danger' : 'good',
      },
    ].filter(Boolean)

    const ModuleHeader = ({ title }) => {
      const colors = NAV_COLORS[activeNavItem.color] || NAV_COLORS.teal
      const Icon = activeNavItem.icon
      return (
        <div className="flex items-center gap-3 mb-6 pb-5 border-b border-slate-100">
          <div className={`p-2.5 rounded-xl border shrink-0 ${colors.iconBg}`}>
            <Icon className="w-5 h-5" />
          </div>
          <h2 className="text-base sm:text-lg font-black text-slate-900 uppercase tracking-wide">{title}</h2>
        </div>
      )
    }

    return (
      <div className="min-h-screen pb-24 animate-fade-in">
        <div className="max-w-7xl mx-auto px-4 space-y-6 pt-6">
          {onReset && (
            <button
              onClick={onReset}
              className="flex items-center gap-2 px-5 py-3 text-xs font-extrabold uppercase tracking-widest text-slate-700 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 hover:border-slate-300 hover:text-slate-900 shadow-sm hover:shadow transition-all duration-150 cursor-pointer select-none"
            >
              <ArrowLeft className="w-4 h-4" />
              Back
            </button>
          )}

          <div className="border border-slate-200 bg-white rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm glow-sage">
            <div>
              <div className="mono text-[10px] text-slate-400 uppercase tracking-widest mb-1 font-bold">Diagnostics Panel</div>
              <h2 className="mono text-lg font-bold text-slate-900 tracking-wide truncate max-w-md">{data.target}</h2>
              <div className="mono text-[11px] text-slate-500 mt-2 flex flex-wrap items-center gap-3 font-semibold">
                {data.resolved_ip !== data.target && (
                  <>
                    <span>Resolved IP: {data.resolved_ip}</span>
                    <span className="text-slate-200">|</span>
                  </>
                )}
                <span>Duration: {data.scan_duration_seconds}s</span>
                <span className="text-slate-200">|</span>
                <span className="uppercase text-teal-600 font-bold">{data.scan_mode === 'fast' ? 'Standard Scan' : 'Deep Scan'}</span>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              {onBatchScan && r?.subdomains?.subdomains && r.subdomains.subdomains.length > 0 && (
                <button
                  onClick={onBatchScan}
                  className="flex items-center gap-1.5 px-3 py-2 bg-amber-50 border border-amber-200 hover:bg-amber-100 text-amber-700 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
                  title={`Scan ${r.subdomains.subdomains.length} discovered subdomains`}
                >
                  <Zap className="w-3.5 h-3.5 text-amber-600" />
                  Scan Subdomains
                </button>
              )}
              <button
                onClick={downloadHtmlReport}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-50 border border-slate-200 text-slate-600 rounded-xl text-[10px] font-bold uppercase tracking-wider mono hover:bg-slate-100 transition shadow-sm cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-slate-500" />
                download html
              </button>
              {onReScan && (
                <button
                  onClick={onReScan}
                  className="flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 border border-indigo-200 text-indigo-700 hover:bg-indigo-100 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-indigo-600" />
                  re-scan
                </button>
              )}
              <button
                onClick={onReset}
                className="flex items-center gap-1.5 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition glow-sage shadow-md cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                new check
              </button>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-4 mt-8 grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-1">
            <div className="border border-slate-200 bg-white rounded-2xl shadow-sm sticky top-20 overflow-y-auto max-h-[calc(100vh-120px)]">
              <div className="p-4 border-b border-slate-100">
                <h3 className="text-[10px] font-extrabold text-slate-400 uppercase tracking-widest">Modules</h3>
              </div>
              <nav className="space-y-2 p-3">
                {MODULE_NAV.filter(item => (!item.domainOnly || data.is_domain) && (!item.deepOnly || isDeep)).map((item) => {
                  const Icon = item.icon
                  const isActive = selectedModule === item.key
                  const colors = NAV_COLORS[item.color] || NAV_COLORS.teal
                  const badge = getModuleBadge(item.key)
                  return (
                    <button
                      key={item.key}
                      onClick={() => setSelectedModule(item.key)}
                      className={`w-full flex items-center gap-2.5 text-left px-3.5 py-3 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 border cursor-pointer ${
                        isActive
                          ? colors.active
                          : 'text-slate-600 border-transparent hover:bg-slate-50 hover:text-slate-900'
                      }`}
                    >
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? '' : 'text-slate-400'}`} />
                      <span className="truncate flex-1">{item.label}</span>
                      {badge && (
                        <span className={`mono text-[9px] font-bold px-1.5 py-0.5 rounded-md shrink-0 ${
                          isActive ? 'bg-white/60' : 'bg-slate-100 text-slate-500'
                        }`}>
                          {badge}
                        </span>
                      )}
                    </button>
                  )
                })}
              </nav>
            </div>
          </div>

          <div className="lg:col-span-3">
            <div className="border border-slate-200 bg-white rounded-2xl p-6 sm:p-8 shadow-sm min-h-[400px]">
              {selectedModule === 'overview' && (
                <div className="space-y-6">
                  <ModuleHeader title="Overview" />

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                    <div className="bg-slate-50 rounded-xl p-4 border border-slate-200">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Target</div>
                      <div className="mono text-sm font-bold text-slate-900 mt-1 break-all">{data.target}</div>
                    </div>
                    <div className="bg-slate-50 rounded-xl p-4 border border-slate-200">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Scan Duration</div>
                      <div className="mono text-sm font-bold text-slate-900 mt-1">{data.scan_duration_seconds}s</div>
                    </div>
                    <div className="bg-slate-50 rounded-xl p-4 border border-slate-200">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Resolved IP</div>
                      <div className="mono text-sm font-bold text-slate-900 mt-1 break-all">{data.resolved_ip}</div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-[11px] font-extrabold text-slate-500 uppercase tracking-widest mb-3">Key Findings</h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {findings.map((f) => {
                        const FIcon = f.icon
                        return (
                          <button
                            key={f.key}
                            onClick={() => setSelectedModule(f.key)}
                            className={`text-left p-4 rounded-xl border transition-all duration-200 hover:shadow-md hover:-translate-y-0.5 cursor-pointer ${TONE_STYLES[f.tone]}`}
                          >
                            <div className="flex items-center gap-2.5 mb-2">
                              <div className={`p-2 rounded-lg ${TONE_ICON[f.tone]}`}>
                                <FIcon className="w-4 h-4" />
                              </div>
                              <span className="text-[10px] font-bold uppercase tracking-wider opacity-70">{f.label}</span>
                            </div>
                            <div className="text-sm font-bold">{f.value}</div>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                </div>
              )}

              {selectedModule === 'dns' && data.is_domain && (
                <div>
                  <ModuleHeader title="DNS Records" />
                  {isOk(r.dns_records) ? <DnsSection data={r.dns_records} /> : <ModuleStatus data={r.dns_records} moduleName="DNS Records" />}
                </div>
              )}

              {selectedModule === 'whois' && data.is_domain && (
                <div>
                  <ModuleHeader title="Domain Registration (WHOIS)" />
                  {isOk(r.whois) ? <WhoisSection data={r.whois} /> : <ModuleStatus data={r.whois} moduleName="WHOIS" />}
                </div>
              )}

              {selectedModule === 'ssl' && (
                <div>
                  <ModuleHeader title="SSL / TLS Certificate" />
                  {isOk(r.ssl_certificate) ? <SslSection data={r.ssl_certificate} /> : <ModuleStatus data={r.ssl_certificate} moduleName="SSL Certificate" />}
                </div>
              )}

              {selectedModule === 'geoip' && (
                <div>
                  <ModuleHeader title="GeoIP Location" />
                  {isOk(r.geo_ip) ? <GeoSection data={r.geo_ip} /> : <ModuleStatus data={r.geo_ip} moduleName="GeoIP" />}
                </div>
              )}

              {selectedModule === 'tech' && (
                <div>
                  <ModuleHeader title="Web Technologies" />
                  {isOk(r.web_technologies) ? <TechSection data={r.web_technologies} /> : <ModuleStatus data={r.web_technologies} moduleName="Web Technologies" />}
                </div>
              )}

              {selectedModule === 'headers' && (
                <div>
                  <ModuleHeader title="HTTP Security Headers" />
                  {isOk(r.http_headers) ? <HeadersSection data={r.http_headers} /> : <ModuleStatus data={r.http_headers} moduleName="Headers" />}
                </div>
              )}

              {selectedModule === 'http_availability' && (
                <div>
                  <ModuleHeader title="HTTP/HTTPS Accessibility" />
                  {isOk(r.http_availability) ? <HttpAvailabilitySection data={r.http_availability} /> : <ModuleStatus data={r.http_availability} moduleName="HTTP Availability" />}
                </div>
              )}

              {selectedModule === 'shodan_intel' && (
                <div>
                  <ModuleHeader title="Shodan Intel" />
                  {isOk(r.shodan_intel) ? <ShodanSection data={r.shodan_intel} /> : <ModuleStatus data={r.shodan_intel} moduleName="Shodan Intel" />}
                </div>
              )}

              {selectedModule === 'waf' && (
                <div>
                  <ModuleHeader title="WAF Detection" />
                  {isOk(r.waf_detect) ? <WafDetectionSection data={r.waf_detect} /> : <ModuleStatus data={r.waf_detect} moduleName="WAF Detection" />}
                </div>
              )}

              {selectedModule === 'ports' && isDeep && (
                <div>
                  <ModuleHeader title="Active Services & Ports" />
                  {r.port_scan && (r.port_scan.status === 'ok' || r.port_scan.status === undefined) ? (
                    <PortsSection data={r.port_scan} />
                  ) : (
                    <ModuleStatus data={r.port_scan} moduleName="Port Scan" />
                  )}
                </div>
              )}

              {selectedModule === 'directories' && isDeep && (
                <div>
                  <ModuleHeader title="Directory Enumeration" />
                  {isOk(r.directories || r.directory_enum) ? (
                    <DirectoriesSection
                      data={r.directories || r.directory_enum}
                      filter={directoryFilter}
                      setFilter={setDirectoryFilter}
                    />
                  ) : (
                    <ModuleStatus data={r.directories || r.directory_enum} moduleName="Directories discovery" />
                  )}
                </div>
              )}

              {selectedModule === 'reverse_dns' && isDeep && (
                <div>
                  <ModuleHeader title="Reverse DNS Pointer (PTR Record)" />
                  {r.reverse_dns && r.reverse_dns.status !== 'skipped' && r.reverse_dns.hostname ? (
                    <div className="mono text-xs bg-slate-50 border border-slate-200 px-4 py-3.5 rounded-xl text-slate-800">
                      <div className="font-semibold text-slate-900">{r.reverse_dns.hostname}</div>
                      {r.reverse_dns.nslookup_resolver_hostname && r.reverse_dns.nslookup_resolver_hostname !== r.reverse_dns.hostname && (
                        <div className="text-[10px] text-slate-500 mt-1">
                          Comparing resolvers: Socket resolution resolved <span className="font-mono font-medium text-slate-700">{r.reverse_dns.primary_resolver_hostname || '—'}</span>, nslookup resolved <span className="font-mono font-medium text-slate-700">{r.reverse_dns.nslookup_resolver_hostname}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <ModuleStatus data={r.reverse_dns} moduleName="Reverse DNS" />
                  )}
                </div>
              )}

              {selectedModule === 'reputation' && isDeep && (
                <div>
                  <ModuleHeader title="IP Reputation & Threat Intelligence" />
                  <div className="grid md:grid-cols-2 gap-6">
                    <AbuseIpdbCard data={r.abuseipdb} onReScan={onReScan} />
                    <VirusTotalCard data={r.virustotal} onReScan={onReScan} />
                  </div>
                </div>
              )}

              {selectedModule === 'email_gather' && isDeep && data.is_domain && (
                <div>
                  <ModuleHeader title="Email Harvesting & OSINT" />
                  <EmailGatherSection data={r.email_gather} />
                </div>
              )}

              {selectedModule === 'subdomains' && data.is_domain && (
                <div>
                  <ModuleHeader title="Subdomains" />
                  {isOk(r.subdomains) ? (
                    <SubdomainsSection
                      data={r.subdomains}
                      searchQuery={subdomainQuery}
                      setSearchQuery={setSubdomainQuery}
                      filter={subdomainFilter}
                      setFilter={setSubdomainFilter}
                    />
                  ) : (
                    <ModuleStatus data={r.subdomains} moduleName="Subdomains" />
                  )}
                </div>
              )}

              {selectedModule === 'cloud' && (
                <div>
                  <ModuleHeader title="Cloud Provider Detection" />
                  {isOk(r.cloud_provider) ? <CloudProviderSection data={r.cloud_provider} r={r} /> : <ModuleStatus data={r.cloud_provider} moduleName="Cloud Provider" />}
                </div>
              )}

              {selectedModule === 'cms' && (
                <div>
                  <ModuleHeader title="CMS Fingerprinting" />
                  {isOk(r.cms_fingerprint) ? (
                    <CmsFingerprintSection data={r.cms_fingerprint} />
                  ) : (
                    <ModuleStatus data={r.cms_fingerprint} moduleName="CMS Fingerprinting" />
                  )}
                </div>
              )}

            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-24 animate-fade-in">
      {onReset && (
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-5 py-3 text-xs font-extrabold uppercase tracking-widest text-slate-700 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 hover:border-slate-300 hover:text-slate-900 shadow-sm hover:shadow transition-all duration-150 cursor-pointer select-none"
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </button>
      )}

      {isBatch && (
        <div className="border border-slate-200 bg-white rounded-2xl p-4 shadow-sm flex flex-col gap-3">
          <div className="mono text-[10px] text-slate-400 uppercase tracking-widest font-bold">Select Target Report ({rawData.results.length} targets)</div>
          <div className="flex flex-wrap gap-2">
            {rawData.results.map((result, idx) => {
              const hasError = !!result.error
              const isSelected = selectedTargetIndex === idx
              return (
                <button
                  key={idx}
                  onClick={() => setSelectedTargetIndex(idx)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all duration-200 border ${
                    isSelected
                      ? 'bg-teal-600 border-teal-600 text-white shadow-sm'
                      : hasError
                        ? 'bg-rose-50 border-rose-200 text-rose-600 hover:bg-rose-100/50'
                        : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  {result.target} {hasError && '(Failed)'}
                </button>
              )
            })}
          </div>
        </div>
      )}

      <div className="border border-slate-200 bg-white rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm glow-sage">
        <div>
          <div className="mono text-[10px] text-slate-400 uppercase tracking-widest mb-1 font-bold">Diagnostics Panel</div>
          <h2 className="mono text-lg font-bold text-slate-900 tracking-wide truncate max-w-md">{data.target}</h2>
          <div className="mono text-[11px] text-slate-500 mt-2 flex flex-wrap items-center gap-3 font-semibold">
            {data.resolved_ip !== data.target && (
              <>
                <span>Resolved IP: {data.resolved_ip}</span>
                <span className="text-slate-200">|</span>
              </>
            )}
            <span>Duration: {data.scan_duration_seconds}s</span>
            <span className="text-slate-200">|</span>
            <span className="uppercase text-teal-600 font-bold">{data.scan_mode === 'fast' ? 'Standard Check' : 'Deep Check'}</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={downloadHtmlReport}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-50 border border-slate-200 text-slate-600 rounded-xl text-[10px] font-bold uppercase tracking-wider mono hover:bg-slate-100 transition shadow-sm cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            download html
          </button>
          {onReScan && (
            <button
              onClick={onReScan}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 border border-indigo-200 text-indigo-700 hover:bg-indigo-100 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5 text-indigo-600" />
              re-scan
            </button>
          )}
          <button
            onClick={onReset}
            className="flex items-center gap-1.5 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition glow-sage shadow-md cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            new check
          </button>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="mono text-xs uppercase tracking-widest font-bold text-slate-800 flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-teal-600" />
              Diagnostic Modules Results
            </h3>
            <p className="text-[11px] text-slate-500 font-semibold mt-0.5">
              Click any module header below to expand and view detailed scan results.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {onBatchScan && r?.subdomains && r.subdomains.subdomains && r.subdomains.subdomains.length > 0 && (
              <button
                onClick={onBatchScan}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-50 border border-amber-200 hover:bg-amber-100 text-amber-700 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
                title={`Scan ${r.subdomains.subdomains.length} discovered subdomains`}
              >
                <Zap className="w-3.5 h-3.5 text-amber-600" />
                Scan Subdomains
              </button>
            )}
            <button
              onClick={() => setAllModulesState(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
            >
              <Eye className="w-3.5 h-3.5 text-teal-600" />
              Expand All
            </button>
            <button
              onClick={() => setAllModulesState(false)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-xl text-[10px] font-bold uppercase tracking-wider mono transition shadow-sm cursor-pointer"
            >
              <EyeOff className="w-3.5 h-3.5 text-slate-400" />
              Collapse All
            </button>
          </div>
        </div>

        <div className="flex w-full overflow-x-auto border border-slate-200 bg-white/75 p-1.5 sm:p-2 rounded-2xl gap-1.5 sticky top-16 z-40 backdrop-blur-md">
          {categoryTabs.map((tab) => {
            const Icon = tab.icon
            const isActive = activeCategory === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveCategory(tab.id)}
                className={`flex-1 min-w-[110px] flex items-center justify-center gap-1.5 sm:gap-2 px-3 py-2.5 rounded-xl text-[10px] md:text-xs font-bold uppercase tracking-wider transition-all duration-200 cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-teal-600 to-cyan-600 text-white shadow-md'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                <span>{tab.label}</span>
              </button>
            )
          })}
        </div>
      </div>

      <div className="space-y-5 pt-2">
        {(activeCategory === 'all' || activeCategory === 'network') && (
          <ModuleAccordionItem
            id="geo_ip"
            title="IP Geolocation, Country & ASN"
            subtitle={
              r.geo_ip
                ? `Country: ${r.geo_ip.country || r.geo_ip.country_name || 'Unknown'} | ASN: ${r.geo_ip.asn || r.geo_ip.as || (typeof r.geo_ip.organization === 'string' ? r.geo_ip.organization.match(/AS\d+/i)?.[0] : null) || '—'} | ISP: ${r.geo_ip.isp || 'N/A'}`
                : "IP Address, Country Location, Datacenter ASN & ISP Provider"
            }
            icon={MapPin}
            accentColor="blue"
            badgeText={
              r.geo_ip?.country
                ? `${r.geo_ip.country} ${r.geo_ip.country_code ? `(${r.geo_ip.country_code})` : ''}`
                : 'GeoIP & ASN'
            }
            isOpen={openModules.geo_ip}
            onToggle={() => toggleModule('geo_ip')}
          >
            {isOk(r.geo_ip) ? <GeoSection data={r.geo_ip} /> : <ModuleStatus data={r.geo_ip} moduleName="GeoIP" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'network') && (
          <ModuleAccordionItem
            id="port_scan"
            title="Active Services & Port Sweeper"
            subtitle="TCP Port Probing & Application Service Banners"
            icon={Server}
            accentColor="indigo"
            badgeText={`${r.port_scan?.open_port_count || 0} Open Ports (${r.port_scan?.scanned_port_count || 0} Probed)`}
            badgeType={r.port_scan?.open_port_count > 0 ? 'warning' : 'default'}
            isOpen={openModules.port_scan}
            onToggle={() => toggleModule('port_scan')}
          >
            {r.port_scan && (r.port_scan.status === 'ok' || r.port_scan.status === undefined) ? (
              <PortsSection data={r.port_scan} />
            ) : (
              <ModuleStatus data={r.port_scan} moduleName="Port Scan" />
            )}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'network') && (
          <ModuleAccordionItem
            id="reverse_dns"
            title="Reverse DNS Pointer (PTR Record)"
            subtitle="Host Resolution & Reverse DNS Pointer Verification"
            icon={Globe}
            accentColor="violet"
            badgeText={data.scan_mode === 'fast' ? 'SKIPPED IN STANDARD CHECK' : (r.reverse_dns?.hostname || 'Reverse DNS')}
            badgeType={data.scan_mode === 'fast' ? 'skipped' : 'default'}
            isOpen={openModules.reverse_dns}
            onToggle={() => toggleModule('reverse_dns')}
          >
            {r.reverse_dns && r.reverse_dns.status !== 'skipped' && r.reverse_dns.hostname ? (
              <div className="mono text-xs bg-slate-50 border border-slate-200 px-4 py-3.5 rounded-xl text-slate-800">
                <div className="font-semibold text-slate-900">{r.reverse_dns.hostname}</div>
                {r.reverse_dns.nslookup_resolver_hostname && r.reverse_dns.nslookup_resolver_hostname !== r.reverse_dns.hostname && (
                  <div className="text-[10px] text-slate-500 mt-1">
                    Comparing resolvers: Socket resolution resolved <span className="font-mono font-medium text-slate-700">{r.reverse_dns.primary_resolver_hostname || '—'}</span>, nslookup resolved <span className="font-mono font-medium text-slate-700">{r.reverse_dns.nslookup_resolver_hostname}</span>
                  </div>
                )}
              </div>
            ) : (
              <ModuleStatus data={r.reverse_dns} moduleName="Reverse DNS" />
            )}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'domain') && data.is_domain && (
          <ModuleAccordionItem
            id="dns_records"
            title="DNS Zone & Records"
            subtitle="Authoritative Zone Records (A, AAAA, MX, NS, TXT, SOA, CAA)"
            icon={Globe}
            accentColor="blue"
            badgeText={`${Object.keys(r.dns_records?.records_by_type || {}).length || 0} Record Types`}
            isOpen={openModules.dns_records}
            onToggle={() => toggleModule('dns_records')}
          >
            {isOk(r.dns_records) ? <DnsSection data={r.dns_records} /> : <ModuleStatus data={r.dns_records} moduleName="DNS Records" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'domain') && data.is_domain && (
          <ModuleAccordionItem
            id="whois"
            title="Domain Registration (WHOIS / RDAP)"
            subtitle={(() => {
              let d = r.whois?.days_until_expiry
              if (d == null && r.whois?.expiration_date) {
                try {
                  const exp = new Date(r.whois.expiration_date)
                  if (!isNaN(exp.getTime())) {
                    d = Math.ceil((exp.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
                  }
                } catch {}
              }
              if (d != null) return `Domain Expiry: ${d} Days Remaining | Registrar: ${r.whois?.registrar || 'RDAP'}`
              return "Registrar Profile, Ownership & Expiration Audit"
            })()}
            icon={FileText}
            accentColor="slate"
            badgeText={(() => {
              let d = r.whois?.days_until_expiry
              if (d == null && r.whois?.expiration_date) {
                try {
                  const exp = new Date(r.whois.expiration_date)
                  if (!isNaN(exp.getTime())) {
                    d = Math.ceil((exp.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
                  }
                } catch {}
              }
              if (d != null) return `${d} Days Left`
              return r.whois?.registrar ? `Registrar: ${r.whois.registrar}` : 'WHOIS'
            })()}
            isOpen={openModules.whois}
            onToggle={() => toggleModule('whois')}
          >
            {isOk(r.whois) ? <WhoisSection data={r.whois} /> : <ModuleStatus data={r.whois} moduleName="WHOIS Details" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'domain') && data.is_domain && (
          <ModuleAccordionItem
            id="subdomains"
            title="Subdomains Index"
            subtitle="Passive OSINT Subdomain Discovery & Resolved IP Mapping"
            icon={Database}
            accentColor="purple"
            badgeText={`${r.subdomains?.count || 0} Discovered`}
            isOpen={openModules.subdomains}
            onToggle={() => toggleModule('subdomains')}
          >
            {isOk(r.subdomains) ? (
              <SubdomainsSection
                data={r.subdomains}
                searchQuery={subdomainQuery}
                setSearchQuery={setSubdomainQuery}
                filter={subdomainFilter}
                setFilter={setSubdomainFilter}
              />
            ) : (
              <ModuleStatus data={r.subdomains} moduleName="Subdomains" />
            )}
          </ModuleAccordionItem>
        )}

        {activeCategory === 'domain' && !data.is_domain && (
          <div className="border border-slate-200 border-t-4 border-t-amber-500 bg-white rounded-2xl p-8 shadow-sm text-center max-w-xl mx-auto my-6">
            <div className="w-16 h-16 rounded-full bg-amber-50 flex items-center justify-center text-amber-500 mx-auto mb-4 border border-amber-100">
              <Globe className="w-8 h-8" />
            </div>
            <h3 className="text-base font-bold text-slate-800 mb-2">Domain-Specific Modules Skipped</h3>
            <p className="text-sm text-slate-500 leading-relaxed font-semibold">
              The target <span className="font-mono bg-slate-50 px-2 py-0.5 border border-slate-200 rounded text-slate-700 font-bold">{data.target}</span> is a direct IP address.
            </p>
            <p className="text-xs text-slate-400 mt-4 leading-relaxed font-semibold">
              DNS records, WHOIS registration, and subdomain index lookups are executed exclusively on domain targets. Check the other categories for Network, Web, and Recon metrics.
            </p>
          </div>
        )}

        {(activeCategory === 'all' || activeCategory === 'web') && (
          <ModuleAccordionItem
            id="ssl_certificate"
            title="SSL / TLS Security Certificate"
            subtitle="Certificate Authority, Expiry Countdown & TLS Cipher Audit"
            icon={Key}
            accentColor="teal"
            badgeText={r.ssl_certificate?.days_until_expiry != null ? `${r.ssl_certificate.days_until_expiry} Days Remaining` : 'SSL'}
            badgeType={r.ssl_certificate?.days_until_expiry < 30 ? 'warning' : 'success'}
            isOpen={openModules.ssl_certificate}
            onToggle={() => toggleModule('ssl_certificate')}
          >
            {isOk(r.ssl_certificate) ? <SslSection data={r.ssl_certificate} /> : <ModuleStatus data={r.ssl_certificate} moduleName="SSL Certificate" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'web') && (
          <ModuleAccordionItem
            id="web_technologies"
            title="Web Application Stack"
            subtitle="Frontend Frameworks, Server Software & JS Libraries"
            icon={Layers}
            accentColor="amber"
            badgeText={`${Object.values(r.web_technologies?.technologies || {}).flat().length || 0} Identified`}
            isOpen={openModules.web_technologies}
            onToggle={() => toggleModule('web_technologies')}
          >
            {isOk(r.web_technologies) ? <TechSection data={r.web_technologies} /> : <ModuleStatus data={r.web_technologies} moduleName="Web Technologies" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'web') && (
          <ModuleAccordionItem
            id="http_headers"
            title="HTTP Security Headers Audit"
            subtitle="HSTS, CSP, X-Frame-Options & Cookie Security Flags"
            icon={ShieldCheck}
            accentColor="cyan"
            badgeText={`${Object.keys(r.http_headers?.security_headers_present || {}).length || 0} Active Headers`}
            isOpen={openModules.http_headers}
            onToggle={() => toggleModule('http_headers')}
          >
            {isOk(r.http_headers) ? <HeadersSection data={r.http_headers} /> : <ModuleStatus data={r.http_headers} moduleName="HTTP Security Headers" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'web') && (
          <ModuleAccordionItem
            id="directory_enum"
            title="Discovered Folders & Directory Fuzzing"
            subtitle="Asynchronous Web Directory & Sensitive Endpoint Sweeper"
            icon={ListFilter}
            accentColor="emerald"
            badgeText={data.scan_mode === 'fast' ? 'SKIPPED IN STANDARD CHECK' : `${r.directories?.paths_found || r.directory_enum?.found?.length || 0} Discovered`}
            badgeType={data.scan_mode === 'fast' ? 'skipped' : 'default'}
            isOpen={openModules.directory_enum}
            onToggle={() => toggleModule('directory_enum')}
          >
            {isOk(r.directories || r.directory_enum) ? (
              <DirectoriesSection
                data={r.directories || r.directory_enum}
                filter={directoryFilter}
                setFilter={setDirectoryFilter}
              />
            ) : (
              <ModuleStatus data={r.directories || r.directory_enum} moduleName="Directories discovery" />
            )}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'recon') && (
          <ModuleAccordionItem
            id="cloud_provider"
            title="Cloud Infrastructure Provider"
            subtitle="Public CIDR Range & Cloud Datacenter Detection"
            icon={Cloud}
            accentColor="sky"
            badgeText={r.cloud_provider?.cloud_detected ? r.cloud_provider.provider : 'Self-Hosted / Non-Cloud'}
            isOpen={openModules.cloud_provider}
            onToggle={() => toggleModule('cloud_provider')}
          >
            {isOk(r.cloud_provider) ? <CloudProviderSection data={r.cloud_provider} r={r} /> : <ModuleStatus data={r.cloud_provider} moduleName="Cloud Provider" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'recon') && (
          <ModuleAccordionItem
            id="waf_detect"
            title="WAF Firewall Detection"
            subtitle="Web Application Firewall Signature & Payload Audit"
            icon={ShieldAlert}
            accentColor="red"
            badgeText={r.waf_detect?.waf_detected ? r.waf_detect.waf_name : 'No WAF Detected'}
            badgeType={r.waf_detect?.waf_detected ? 'warning' : 'default'}
            isOpen={openModules.waf_detect}
            onToggle={() => toggleModule('waf_detect')}
          >
            {isOk(r.waf_detect) ? <WafDetectionSection data={r.waf_detect} /> : <ModuleStatus data={r.waf_detect} moduleName="WAF Detection" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'recon') && (
          <ModuleAccordionItem
            id="cms_fingerprint"
            title="CMS Platform Identification"
            subtitle="WordPress, Joomla, Drupal & CMS Asset Fingerprinting"
            icon={Fingerprint}
            accentColor="fuchsia"
            badgeText={r.cms_fingerprint?.cms_detected ? r.cms_fingerprint.cms : 'No CMS Engine'}
            isOpen={openModules.cms_fingerprint}
            onToggle={() => toggleModule('cms_fingerprint')}
          >
            {isOk(r.cms_fingerprint) ? <CmsFingerprintSection data={r.cms_fingerprint} /> : <ModuleStatus data={r.cms_fingerprint} moduleName="CMS Fingerprinting" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'domain') && data.is_domain && (
          <ModuleAccordionItem
            id="email_gather"
            title="Email Harvesting & OSINT Discovery"
            subtitle="Domain-Associated Email Addresses, Employee Accounts & Public Leak Exposures"
            icon={Mail}
            accentColor="violet"
            badgeText={data.scan_mode === 'fast' ? 'SKIPPED IN STANDARD CHECK' : `${r.email_gather?.total_found || r.email_gather?.emails?.length || 0} Discovered`}
            badgeType={data.scan_mode === 'fast' ? 'skipped' : 'default'}
            isOpen={openModules.email_gather}
            onToggle={() => toggleModule('email_gather')}
          >
            {isOk(r.email_gather) ? <EmailGatherSection data={r.email_gather} /> : <ModuleStatus data={r.email_gather} moduleName="Email Harvesting" />}
          </ModuleAccordionItem>
        )}

        {(activeCategory === 'all' || activeCategory === 'recon') && (
          <ModuleAccordionItem
            id="threats"
            title="Threat Intelligence & IP Reputation"
            subtitle="AbuseIPDB Threat Reports & VirusTotal Engine Flags"
            icon={Shield}
            accentColor="rose"
            badgeText="Threat Intelligence"
            isOpen={openModules.threats}
            onToggle={() => toggleModule('threats')}
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <AbuseIpdbCard data={r.abuseipdb} onReScan={onReScan} />
              <VirusTotalCard data={r.virustotal} onReScan={onReScan} />
            </div>
          </ModuleAccordionItem>
        )}
      </div>
    </div>
  )
}

function OverviewTab({ r, data, isOk }) {
  const openPorts = r.port_scan?.open_port_count || 0
  const subdomainsCount = r.subdomains?.count || 0

  const sslDays = r.ssl_certificate?.days_until_expiry
  const sslStatus = sslDays === null || sslDays === undefined ? 'Unknown' : sslDays < 0 ? 'Expired' : `${sslDays} Days Left`
  const sslColor = sslDays === null || sslDays === undefined ? 'text-slate-400 font-bold' : sslDays < 0 ? 'text-red-600 font-extrabold' : sslDays < 30 ? 'text-amber-505 text-amber-500 font-bold' : 'text-teal-700 font-bold'

  const country = r.geo_ip?.country || 'Unknown'
  const countryCode = r.geo_ip?.country_code
  const isp = r.geo_ip?.isp || 'Unknown'

  const abuseScore = r.abuseipdb?.abuse_confidence_score
  const vtDetections = r.virustotal?.detection_stats?.malicious

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div className="border border-slate-200 border-t-4 border-t-blue-500 bg-white rounded-2xl p-5 md:col-span-2 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-3.5 border-b border-slate-100 pb-2">
            <Globe className="w-4 h-4 text-blue-600" />
            <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Server Location</span>
          </div>
          <div className="space-y-2.5 mono text-xs">
            <div className="flex justify-between border-b border-slate-100 pb-1.5">
              <span className="text-slate-400 font-bold uppercase text-[9px]">ISP Provider</span>
              <span className="text-slate-900 font-bold truncate max-w-[200px]" title={isp}>{isp}</span>
            </div>
            <div className="flex justify-between border-b border-slate-100 pb-1.5">
              <span className="text-slate-400 font-bold uppercase text-[9px]">ASN Code</span>
              <span className="text-slate-900 font-bold">{r.geo_ip?.asn || '—'}</span>
            </div>
            <div className="flex justify-between pb-0.5">
              <span className="text-slate-400 font-bold uppercase text-[9px]">Country</span>
              <span className="text-slate-900 font-bold">{countryCode ? `${country} (${countryCode})` : country}</span>
            </div>
          </div>
        </div>
        {r.geo_ip?.latitude && (
          <div className="mt-4 pt-3 border-t border-slate-100 text-[10px] text-slate-500 font-bold flex items-center gap-1.5 mono">
            <MapPin className="w-3.5 h-3.5 text-slate-450" />
            Coords: {r.geo_ip.latitude}, {r.geo_ip.longitude}
          </div>
        )}
      </div>

      <div className="border border-slate-200 border-t-4 border-t-teal-500 bg-white rounded-2xl p-5 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
            <Key className="w-4 h-4 text-teal-600" />
            <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">SSL Certificate</span>
          </div>
          <div className="mt-3">
            <div className={`text-2xl font-extrabold tracking-tight ${sslColor}`}>{sslStatus}</div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1.5 mono font-bold">Security Expiry</div>
          </div>
        </div>
        {isOk(r.ssl_certificate) && (
          <div className="text-[10px] text-slate-500 font-bold font-mono mt-4 truncate max-w-full">
            Issuer: {r.ssl_certificate.issuer_common_name}
          </div>
        )}
      </div>

      <div className="border border-slate-200 border-t-4 border-t-indigo-500 bg-white rounded-2xl p-5 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
            <Server className="w-4 h-4 text-indigo-600" />
            <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Active Services</span>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-extrabold text-slate-900 tracking-tight">{openPorts}</div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1.5 mono font-bold">Open Ports</div>
          </div>
        </div>
        <div className="text-[10px] text-slate-500 font-bold font-mono mt-4">
          Probed {r.port_scan?.scanned_port_count || 0} ports
        </div>
      </div>

      {data.is_domain && (
        <div className="border border-slate-200 border-t-4 border-t-purple-500 bg-white rounded-2xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
              <Database className="w-4 h-4 text-purple-650 text-purple-600" />
              <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Subdomains</span>
            </div>
            <div className="mt-3">
              <div className="text-3xl font-extrabold text-slate-900 tracking-tight">{subdomainsCount}</div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1.5 mono font-bold">Discovered</div>
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-bold font-mono mt-4">
            Passive index verification
          </div>
        </div>
      )}

      {data.is_domain && (r.email_gather?.emails || r.email_gather?.total_found > 0) && (
        <div className="border border-slate-200 border-t-4 border-t-violet-500 bg-white rounded-2xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
              <Mail className="w-4 h-4 text-violet-600" />
              <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Email Harvesting</span>
            </div>
            <div className="mt-3">
              <div className="text-3xl font-extrabold text-slate-900 tracking-tight">{r.email_gather?.total_found || r.email_gather?.emails?.length || 0}</div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1.5 mono font-bold">Emails Discovered</div>
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-bold font-mono mt-4">
            OSINT & Public Leak Records
          </div>
        </div>
      )}

      {(abuseScore !== undefined || vtDetections !== undefined) && (
        <div className="border border-slate-200 border-t-4 border-t-rose-500 bg-white rounded-2xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
              <ShieldAlert className="w-4 h-4 text-rose-600" />
              <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Threat Reputation</span>
            </div>
            <div className="space-y-2 mt-3 mono text-[11px]">
              {abuseScore !== undefined && (
                <div className="flex justify-between items-center">
                  <span className="text-slate-500 font-bold">Abuse IPDB Score</span>
                  <span className={`font-extrabold ${abuseScore > 10 ? 'text-red-600' : 'text-emerald-700'}`}>{abuseScore}%</span>
                </div>
              )}
              {vtDetections !== undefined && (
                <div className="flex justify-between items-center">
                  <span className="text-slate-500 font-bold">VirusTotal Flags</span>
                  <span className={`font-extrabold ${vtDetections > 0 ? 'text-red-650 text-red-600' : 'text-teal-700'}`}>{vtDetections} Engines</span>
                </div>
              )}
            </div>
          </div>
          <div className="text-[10px] text-slate-450 font-mono mt-4 uppercase font-bold tracking-wider">
            Reputation database checked
          </div>
        </div>
      )}

      {isOk(r.web_technologies) && Object.keys(r.web_technologies.technologies || {}).length > 0 && (
        <div className="border border-slate-200 border-t-4 border-t-amber-500 bg-white rounded-2xl p-5 md:col-span-2 shadow-sm">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-100 pb-2">
            <Layers className="w-4 h-4 text-amber-600" />
            <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Web Stack Platform</span>
          </div>
          <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
            {Object.values(r.web_technologies.technologies).flatMap(techList => techList).slice(0, 10).map((tech, idx) => (
              <span key={tech + '-' + idx} className="mono text-[10px] px-2.5 py-1 bg-slate-50 border border-slate-200 rounded text-slate-800 font-bold">
                {tech}
              </span>
            ))}
          </div>
        </div>
      )}

      {isOk(r.http_headers) && (
        <div className="border border-slate-200 border-t-4 border-t-cyan-500 bg-white rounded-2xl p-5 md:col-span-2 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3 border-b border-slate-100 pb-2">
              <Activity className="w-4 h-4 text-cyan-600" />
              <span className="mono text-[10px] text-slate-500 uppercase tracking-wider font-bold">Security Headers</span>
            </div>
            <div className="space-y-2 mt-3 mono text-[11px]">
              <div className="flex justify-between items-center">
                <span className="text-slate-500 font-bold">HTTP status code</span>
                <span className="text-slate-900 font-extrabold">{r.http_headers.http_status} {r.http_headers.reason}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500 font-bold">Configured Headers</span>
                <span className="text-teal-700 font-extrabold">{Object.keys(r.http_headers.security_headers_present || {}).length} Active</span>
              </div>
            </div>
          </div>
          <div className="text-[10px] text-slate-450 mt-4 leading-normal truncate font-mono font-bold">
            Target: {r.http_headers.url}
          </div>
        </div>
      )}

      {data.scan_mode === 'fast' && (
        <div className="border border-slate-200 bg-white/70 p-4 rounded-2xl md:col-span-4 flex items-start gap-3 shadow-inner">
          <Fingerprint className="w-5 h-5 text-slate-500 flex-shrink-0 mt-0.5 animate-pulse" />
          <div>
            <div className="mono text-[10px] text-slate-500 uppercase tracking-widest font-bold">Deep Check Diagnostic Modules Skipped</div>
            <div className="text-[11px] text-slate-655 text-slate-600 mt-1.5 leading-relaxed font-semibold">
              To guarantee maximum execution speed, **Directory brute-forcing (directory fuzzing)** and **Reverse DNS Host resolution** are bypassed in Standard Check. Run a <span className="font-semibold text-teal-650 text-teal-650 text-teal-605 text-teal-600">Deep Check</span> scan to include these deep security analysis modules.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ModuleSummary({ summary }) {
  const okCount = summary.ok?.length || 0
  const errCount = summary.error?.length || 0
  const skipCount = summary.skipped?.length || 0
  const partialCount = summary.partial?.length || 0

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mono text-xs">
      <div className="border border-slate-200 bg-white rounded-xl p-4 flex flex-col justify-between h-20 shadow-sm">
        <div className="text-emerald-600 text-3xl font-extrabold">{okCount}</div>
        <div className="text-[10px] text-stone-400 uppercase tracking-widest font-semibold">Checks OK</div>
      </div>
      <div className="border border-slate-200 bg-white rounded-xl p-4 flex flex-col justify-between h-20 shadow-sm">
        <div className={`text-3xl font-extrabold ${partialCount > 0 ? 'text-amber-500' : 'text-stone-300'}`}>
          {partialCount}
        </div>
        <div className="text-[10px] text-stone-400 uppercase tracking-widest font-semibold">Partial Data</div>
      </div>
      <div className="border border-slate-200 bg-white rounded-xl p-4 flex flex-col justify-between h-20 shadow-sm">
        <div className={`text-3xl font-extrabold ${errCount > 0 ? 'text-red-500' : 'text-stone-300'}`}>
          {errCount}
        </div>
        <div className="text-[10px] text-stone-400 uppercase tracking-widest font-semibold">Failed</div>
      </div>
      <div className="border border-slate-200 bg-white rounded-xl p-4 flex flex-col justify-between h-20 shadow-sm">
        <div className="text-stone-400 text-3xl font-extrabold">{skipCount}</div>
        <div className="text-[10px] text-stone-400 uppercase tracking-widest font-semibold">Skipped</div>
      </div>
    </div>
  )
}

export function AbuseIpdbCard({ data, onReScan }) {
  const [abuseInputKey, setAbuseInputKey] = useState('')
  if (!data) return null
  const container = 'border border-orange-200 border-t-4 border-t-orange-500 bg-white rounded-2xl p-5 shadow-sm'
  const title = (
    <div className="mono text-[10px] uppercase tracking-widest text-orange-800 mb-4 font-bold flex items-center gap-1.5">
      <ShieldAlert className="w-3.5 h-3.5 text-orange-600" />
      AbuseIPDB Threat Reputation
    </div>
  )

  if (data.status !== 'ok') {
    return (
      <div className={container}>
        {title}
        <ModuleStatus data={data} moduleName="AbuseIPDB" />
        {(data.error_code === 'api_key_missing' || data.status === 'error') && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const k = abuseInputKey.trim()
              if (!k) return
              try { localStorage.setItem('recon_abuseipdb_key', k) } catch {}
              if (onReScan) onReScan({ abuseipdbApiKey: k })
            }}
            className="mt-4 pt-3 border-t border-orange-100 space-y-2"
          >
            <div className="text-[11px] font-bold uppercase tracking-wider text-orange-800 mono flex items-center justify-between">
              <span>Provide AbuseIPDB API Key:</span>
              <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer" className="text-teal-600 hover:underline normal-case font-semibold text-[10px]">Get Free Key →</a>
            </div>
            <div className="flex gap-2">
              <input
                type="password"
                value={abuseInputKey}
                onChange={(e) => setAbuseInputKey(e.target.value)}
                placeholder="Paste AbuseIPDB API key..."
                className="flex-1 px-3 py-2 text-xs border border-orange-200 rounded-xl focus:outline-none focus:border-orange-500 font-mono bg-orange-50/20"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white font-bold text-[10px] uppercase tracking-wider mono rounded-xl transition shadow-md cursor-pointer"
              >
                Save Key & Rescan
              </button>
            </div>
          </form>
        )}
      </div>
    )
  }

  const score = data.abuse_confidence_score
  const scoreColor = score >= 75 ? 'text-red-650 text-red-600 font-extrabold' : score >= 25 ? 'text-amber-500 font-bold' : 'text-teal-700 font-bold'

  return (
    <div className={container}>
      {title}
      <div className="flex items-baseline gap-3">
        <div className={`mono text-4xl font-extrabold ${scoreColor}`}>{score}%</div>
        <div className="mono text-[9px] text-slate-400 uppercase tracking-wider font-bold">abuse confidence score</div>
      </div>
      <div className="mt-4 mb-1 mono text-xs font-semibold text-slate-700">
        This IP was reported {data.total_reports || 0} times. Confidence of Abuse is {score}%
      </div>
      <div className="mt-5 grid grid-cols-2 gap-4 border-t border-slate-100 pt-4 mono text-xs">
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Total Reports</div>
          <div className="text-slate-800 text-base font-bold mt-0.5">{data.total_reports}</div>
        </div>
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Distinct Reporters</div>
          <div className="text-slate-800 text-base font-bold mt-0.5">{data.num_distinct_users}</div>
        </div>
        <div className="col-span-2">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Usage Type</div>
          <div className="text-slate-600 mt-0.5 truncate font-semibold">{data.usage_type || '—'}</div>
        </div>
        {data.last_reported_at && (
          <div className="col-span-2">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Last Reported</div>
            <div className="text-slate-600 mt-0.5 font-semibold">
              {new Date(data.last_reported_at).toLocaleString()}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export function VirusTotalCard({ data, onReScan }) {
  const [vtInputKey, setVtInputKey] = useState('')
  if (!data) return null
  const container = 'border border-rose-200 border-t-4 border-t-rose-500 bg-white rounded-2xl p-5 shadow-sm'
  const title = (
    <div className="mono text-[10px] uppercase tracking-widest text-rose-800 mb-4 font-bold flex items-center gap-1.5">
      <ShieldCheck className="w-3.5 h-3.5 text-rose-600" />
      VirusTotal Engine Checks
    </div>
  )

  if (data.status !== 'ok') {
    return (
      <div className={container}>
        {title}
        <ModuleStatus data={data} moduleName="VirusTotal" />
        {(data.error_code === 'api_key_missing' || data.status === 'error') && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const k = vtInputKey.trim()
              if (!k) return
              try { localStorage.setItem('recon_virustotal_key', k) } catch {}
              if (onReScan) onReScan({ virustotalApiKey: k })
            }}
            className="mt-4 pt-3 border-t border-rose-100 space-y-2"
          >
            <div className="text-[11px] font-bold uppercase tracking-wider text-rose-800 mono flex items-center justify-between">
              <span>Provide VirusTotal API Key:</span>
              <a href="https://www.virustotal.com/gui/my-api-key" target="_blank" rel="noreferrer" className="text-teal-600 hover:underline normal-case font-semibold text-[10px]">Get Free Key →</a>
            </div>
            <div className="flex gap-2">
              <input
                type="password"
                value={vtInputKey}
                onChange={(e) => setVtInputKey(e.target.value)}
                placeholder="Paste VirusTotal API key..."
                className="flex-1 px-3 py-2 text-xs border border-rose-200 rounded-xl focus:outline-none focus:border-rose-500 font-mono bg-rose-50/20"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold text-[10px] uppercase tracking-wider mono rounded-xl transition shadow-md cursor-pointer"
              >
                Save Key & Rescan
              </button>
            </div>
          </form>
        )}
      </div>
    )
  }

  const stats = data.detection_stats
  const badCount = (stats?.malicious || 0) + (stats?.suspicious || 0)
  const total = stats?.total_engines

  return (
    <div className={container}>
      {title}
      <div className="flex items-baseline gap-2">
        <div className={`mono text-4xl font-extrabold ${badCount > 0 ? 'text-red-650 text-red-600 font-extrabold' : 'text-teal-700'}`}>
          {badCount}
          <span className="text-slate-400 text-xl font-normal">/{total}</span>
        </div>
        <div className="mono text-[9px] text-slate-400 uppercase tracking-wider font-bold">malicious engine flags</div>
      </div>
      <div className="mt-5 grid grid-cols-2 gap-3 border-t border-slate-100 pt-4 mono text-xs">
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Malicious</div>
          <div className="text-red-500 font-bold mt-0.5">{stats?.malicious || 0}</div>
        </div>
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Suspicious</div>
          <div className="text-amber-500 font-bold mt-0.5">{stats?.suspicious || 0}</div>
        </div>
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Harmless</div>
          <div className="text-teal-700 font-bold mt-0.5">{stats?.harmless || 0}</div>
        </div>
        <div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Undetected</div>
          <div className="text-slate-500 font-bold mt-0.5">{stats?.undetected || 0}</div>
        </div>
      </div>
      {data.flagged_by?.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-100">
          <div className="mono text-[9px] text-slate-400 tracking-widest uppercase font-bold mb-2">Flagged Registries</div>
          <div className="flex flex-wrap gap-1">
            {data.flagged_by.slice(0, 5).map((f) => (
              <span key={f.engine} className="mono text-[9px] px-2 py-0.5 bg-red-50 border border-red-200 rounded text-red-700 font-bold">
                {f.engine}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function KVGrid({ pairs, singleColumn = false }) {
  if (!pairs || !Array.isArray(pairs)) return null
  return (
    <div className={`grid grid-cols-1 ${singleColumn ? '' : 'md:grid-cols-2'} gap-x-8 gap-y-1 mono text-xs`}>
      {pairs.filter((p) => p && p[1] !== null && p[1] !== undefined && p[1] !== '').map(([k, v]) => (
        <div key={k} className="flex items-start sm:items-center justify-between border-b border-slate-100 py-2.5 font-semibold">
          <span className="text-[9.5px] text-slate-450 uppercase tracking-wider font-bold pr-4 shrink-0">{k}</span>
          <span className={`text-slate-800 font-mono font-bold text-right ${singleColumn ? 'break-all' : 'truncate max-w-xs'}`}>{String(v)}</span>
        </div>
      ))}
    </div>
  )
}

function LazyMapFrame({ src, title }) {
  const containerRef = useRef(null)
  const [visible, setVisible] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const hasLoadedRef = useRef(false)
  const wasVisibleRef = useRef(false)

  useEffect(() => {
    if (!containerRef.current) return
    const observer = new IntersectionObserver(
      (entries) => {
        const isIntersecting = entries[0]?.isIntersecting
        if (isIntersecting && !wasVisibleRef.current) {
          if (!hasLoadedRef.current) {
            hasLoadedRef.current = true
            setVisible(true)
          } else {
            setReloadKey((k) => k + 1)
          }
        }
        wasVisibleRef.current = isIntersecting
      },
      { rootMargin: '150px' }
    )
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  return (
    <div ref={containerRef} className="w-full h-64 sm:h-80 bg-slate-100 relative">
      {visible ? (
        <iframe key={reloadKey} title={title} className="w-full h-full" style={{ border: 0 }} src={src} />
      ) : (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-5 h-5 border-2 border-slate-300 border-t-teal-500 rounded-full animate-spin" />
        </div>
      )}
    </div>
  )
}

export function RetriedNotice({ data }) {
  if (!data?.retried) return null
  return (
    <div
      className="mono text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 flex items-center gap-1.5 mb-3"
      title={data.first_attempt_note}
    >
      <RefreshCw className="w-3 h-3 flex-shrink-0" />
      Succeeded on a second attempt — the first attempt hit a transient issue
    </div>
  )
}

export function GeoSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No location details available.</div>

  const countryName = data.country || data.country_name || 'Unknown'
  const countryCode = data.country_code || data.countryCode
  const displayCountry = countryCode && !countryName.includes(`(${countryCode})`) ? `${countryName} (${countryCode})` : countryName

  const extractedAsn = data.asn || data.as || data.asn_code || data.as_number || (typeof data.organization === 'string' ? data.organization.match(/AS\d+/i)?.[0] : null) || '—'

  const lat = parseFloat(data.latitude)
  const lon = parseFloat(data.longitude)
  const hasCoords = !isNaN(lat) && !isNaN(lon)

  const fields = [
    ['IP Address', data.ip || 'N/A'],
    ['Country', displayCountry],
    ['ASN Number', extractedAsn],
    ['Region / State', data.region || '—'],
    ['City', data.city || '—'],
    ['Coordinates', hasCoords ? `${data.latitude}, ${data.longitude}` : '—'],
    ['Timezone', data.timezone || '—'],
    ['ISP Provider', data.isp || '—'],
    ['Organization', data.organization || data.org || '—'],
    ['Hosting Server', data.is_hosting !== undefined ? (data.is_hosting ? 'Yes (Cloud/Server)' : 'No') : 'No'],
    ['Proxy / VPN Network', data.is_proxy !== undefined ? (data.is_proxy ? 'Yes' : 'No') : 'No'],
  ]

  return (
    <div className="space-y-5">
      <RetriedNotice data={data} />
      {hasCoords && (
        <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          <LazyMapFrame
            title="Server Location Map"
            src={`https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.08}%2C${lat - 0.05}%2C${lon + 0.08}%2C${lat + 0.05}&layer=mapnik&marker=${lat}%2C${lon}`}
          />
          <div className="bg-slate-50 border-t border-slate-200 px-4 py-2 flex items-center justify-between">
            <span className="mono text-[10px] text-slate-500 font-semibold">{data.city || displayCountry} &middot; {lat.toFixed(4)}, {lon.toFixed(4)}</span>
            <a
              href={`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=12/${lat}/${lon}`}
              target="_blank"
              rel="noreferrer"
              className="text-[10px] font-bold text-teal-600 hover:text-teal-800 hover:underline"
            >
              View Larger Map →
            </a>
          </div>
        </div>
      )}
      <KVGrid pairs={fields} singleColumn={true} />
    </div>
  )
}

const DnsRecordTable = ({ type, records }) => {
  if (!records || records.length === 0) return null
  const isObject = typeof records[0] === 'object'
  if (!isObject) {
    return (
      <div className="overflow-x-auto w-full border border-blue-200 rounded shadow-sm bg-white">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-blue-50/50 text-[9px] uppercase tracking-widest text-blue-800 font-bold border-b border-blue-150">
              <th className="px-4 py-2 whitespace-nowrap w-24">Type</th>
              <th className="px-4 py-2">Record / Address</th>
            </tr>
          </thead>
          <tbody className="mono text-[11px] text-slate-800">
            {records.map((rec, i) => (
              <tr key={i} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/50 transition-colors">
                <td className="px-4 py-2 font-bold text-blue-600 whitespace-nowrap">{type}</td>
                <td className="px-4 py-2 break-all">{rec}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  const keys = Object.keys(records[0])
  return (
    <div className="overflow-x-auto w-full border border-blue-200 rounded shadow-sm bg-white">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="bg-blue-50/50 text-[9px] uppercase tracking-widest text-blue-800 font-bold border-b border-blue-150">
            <th className="px-4 py-2 whitespace-nowrap w-24">Type</th>
            {keys.map((k) => (
              <th key={k} className="px-4 py-2 whitespace-nowrap">{k.replace(/_/g, ' ')}</th>
            ))}
          </tr>
        </thead>
        <tbody className="mono text-[11px] text-slate-800">
          {records.map((rec, i) => (
            <tr key={i} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/50 transition-colors">
              <td className="px-4 py-2 font-bold text-blue-600 whitespace-nowrap">{type}</td>
              {keys.map((k) => (
                <td key={k} className="px-4 py-2 break-all">{String(rec[k])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function DnsSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No DNS records available.</div>
  const records = data.records_by_type || {}
  const orderedKeys = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "SPF", "DMARC", "DKIM"]

  const coreTypes = ["A", "NS", "SOA"]
  const domainNotFound = coreTypes.every((t) => records[t]?.status === 'nxdomain')

  return (
    <div className="space-y-4 font-semibold">
      <RetriedNotice data={data} />
      {domainNotFound && (
        <div className="flex items-start gap-2 bg-red-50/40 border border-red-200 rounded-xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
          <p className="text-[11px] text-red-700 font-semibold leading-relaxed">
            This domain does not exist (NXDOMAIN) — its nameservers report no such domain is
            registered. The rows below reflect that every record type comes back empty for the
            same reason, not that the domain is simply unconfigured.
          </p>
        </div>
      )}
      {orderedKeys.map((type) => {
        const result = records[type]
        if (!result) return null
        if (result.status === 'error' || result.status === 'timeout') {
          return (
            <div key={type} className="border border-blue-150 bg-blue-50/20 rounded-xl p-3">
              <div className="mono text-[10px] text-blue-800 uppercase tracking-widest font-bold mb-1.5">{type}</div>
              <ModuleStatus data={result} moduleName={`DNS ${type}`} />
            </div>
          )
        }
        const recs = result.records || []
        return (
          <div key={type} className="border border-blue-150 bg-blue-50/20 rounded-xl p-3">
            <div className="mono text-[10px] text-blue-800 uppercase tracking-widest font-bold mb-1.5">{type}</div>
            {recs.length === 0 ? (
              <div className="mono text-xs text-slate-400 bg-white px-3 py-2.5 border border-blue-100 rounded italic font-semibold">
                {result.status === 'nxdomain' ? 'This hostname does not exist (NXDOMAIN).' : `No ${type} records configured.`}
              </div>
            ) : (
              <DnsRecordTable type={type} records={recs} />
            )}
          </div>
        )
      })}
    </div>
  )
}

export function WhoisSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No registration details available.</div>

  let daysLeft = data.days_until_expiry
  if (daysLeft == null && data.expiration_date) {
    try {
      const expDate = new Date(data.expiration_date)
      if (!isNaN(expDate.getTime())) {
        const now = new Date()
        const diffTime = expDate.getTime() - now.getTime()
        daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
      }
    } catch {}
  }

  const abuseEmail = data.registrar_abuse_email || (Array.isArray(data.emails) && data.emails.length > 0 ? data.emails.join(', ') : null)
  const statusFlagsStr = Array.isArray(data.status_flags) && data.status_flags.length > 0 ? data.status_flags.slice(0, 3).join(', ') : (typeof data.status === 'string' ? data.status : null)

  const allFields = [
    ['Registrar Host', data.registrar],
    ['Registrar IANA ID', data.registrar_iana_id],
    ['Registrar Abuse Email', abuseEmail],
    ['Registrar Abuse Phone', data.registrar_abuse_phone],
    ['Registry Domain ID', data.registry_domain_id],
    ['Registered Date', formatDate(data.creation_date)],
    ['Expiration Date', formatDate(data.expiration_date)],
    ['Expiry in Days', daysLeft != null ? `${daysLeft} Days ${daysLeft > 0 ? 'Remaining' : '(Expired)'}` : null],
    ['Last Modified Date', formatDate(data.updated_date)],
    ['Expiry Status', data.expiry_status || (daysLeft != null ? (daysLeft > 0 ? 'Active' : 'Expired') : null)],
    ['Registrant Name', data.registrant_name],
    ['Registrant Organization', data.registrant_org || data.org],
    ['Registrant Country', data.country],
    ['Registrant State', data.state],
    ['Registrant City', data.city],
    ['Domain Status Flags', statusFlagsStr],
    ['DNSSEC Status', data.dnssec],
  ]

  const fields = allFields.filter(([k, v]) => v && v !== '—' && v !== 'N/A' && v !== 'null' && v !== 'None' && String(v).trim() !== '')

  return (
    <div className="space-y-4">
      <RetriedNotice data={data} />
      {daysLeft != null && (
        <div className="flex items-center gap-2 mb-2">
          <span className={`mono text-xs font-extrabold px-3 py-1.5 rounded-lg border shadow-sm ${
            daysLeft < 30 ? 'bg-amber-50 border-amber-200 text-amber-700' : 'bg-emerald-50 border-emerald-200 text-emerald-800'
          }`}>
            ⏳ Domain Expiry: {daysLeft > 0 ? `${daysLeft} Days Remaining` : `Expired ${-daysLeft} Days Ago`}
          </span>
        </div>
      )}
      <KVGrid pairs={fields} singleColumn={true} />
      {data.name_servers?.length > 0 && (
        <div className="pt-3 border-t border-slate-200">
          <div className="mono text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">Nameservers</div>
          <div className="mono text-xs space-y-1 max-h-40 overflow-y-auto">
            {data.name_servers.map((ns) => (
              <div key={ns} className="text-slate-700 bg-white border border-slate-250 px-3 py-1.5 rounded font-bold shadow-sm">{ns}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function SslSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No certificate details available.</div>
  const days = data.days_until_expiry
  const expiryColor = days === null || days === undefined ? 'text-teal-700' : days < 0 ? 'text-red-600 font-extrabold' : days < 30 ? 'text-amber-500 font-bold' : 'text-teal-700 font-bold'
  const fields = [
    ['Common Name (CN)', data.subject_common_name],
    ['Certificate Issuer', data.issuer_common_name],
    ['Issuer Org', data.issuer_organization],
    ['Valid From', data.valid_from],
    ['Valid Until', data.valid_until],
    ['Negotiated Protocol', data.protocol],
    ['Negotiated Cipher', data.cipher_suite],
  ]
  return (
    <div className="space-y-5">
      <RetriedNotice data={data} />
      {days !== null && days !== undefined && (
        <div className={`mono text-xs font-semibold px-3 py-1.5 rounded border inline-block ${days < 0 ? 'bg-red-50 border-red-200 text-red-750 text-red-700 font-bold' : 'bg-white border-teal-200 text-teal-900 font-bold'
          }`}>
          Status: <span className={expiryColor}>{days < 0 ? `Expired ${-days} days ago` : `Expires in ${days} days`}</span>
        </div>
      )}

      <KVGrid pairs={fields} singleColumn={true} />

      {data.supported_protocols && Object.keys(data.supported_protocols).length > 0 && (
        <div className="pt-4 border-t border-teal-150">
          <div className="mono text-[10px] text-teal-800 tracking-widest uppercase font-bold mb-3">
            Supported TLS Protocols & Cipher Suites
          </div>
          <div className="border border-teal-150 rounded-xl overflow-hidden shadow-sm bg-white font-semibold">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-teal-50/50 text-[9px] uppercase tracking-widest text-teal-800 font-bold border-b border-teal-150">
                  <th className="px-4 py-3 w-1/4">Protocol</th>
                  <th className="px-4 py-3 w-3/4">Supported Cipher Suites</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(data.supported_protocols).map(([proto, ciphers], idx, arr) => (
                  <tr key={proto} className={`border-b border-teal-50 hover:bg-teal-50/10 transition ${idx === arr.length - 1 ? 'border-b-0' : ''}`}>
                    <td className="px-4 py-4 valign-top font-bold align-top">
                      <span className="mono text-[10px] bg-teal-600 border border-teal-250 text-white px-2.5 py-1 rounded font-extrabold uppercase tracking-wider shadow-sm">
                        {proto}
                      </span>
                      <div className="mono text-[9px] text-slate-400 font-semibold mt-2.5">
                        {ciphers.length} cipher(s)
                      </div>
                    </td>
                    <td className="px-4 py-4 font-mono">
                      <div className="flex flex-col gap-1.5">
                        {ciphers.map((cipher) => (
                          <div key={cipher} className="mono text-[9.5px] px-3 py-1.5 bg-slate-50 border border-slate-150 rounded text-slate-800 font-bold break-all shadow-sm">
                            {cipher}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data.subject_alternative_names?.length > 0 && (
        <div className="pt-4 border-t border-teal-150">
          <div className="mono text-[10px] text-teal-800 tracking-widest uppercase font-bold mb-2.5">
            Alternative Subject Names (SANs)
          </div>
          <div className="flex flex-wrap gap-1">
            {data.subject_alternative_names.map((san) => (
              <span key={san} className="mono text-[9.5px] px-2.5 py-1 bg-white border border-teal-150 rounded text-teal-800 font-bold shadow-sm">
                {san}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function ShodanSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No Shodan intel available.</div>

  if (data.has_data === false) {
    return (
      <div className="space-y-3">
        <RetriedNotice data={data} />
        <div className="mono text-xs text-slate-400 bg-white px-3 py-2.5 border border-slate-200 rounded italic font-semibold text-center">
          {data.note || 'No Shodan data available for this IP.'}
        </div>
      </div>
    )
  }

  const ports = data.ports || []
  const hostnames = data.hostnames || []
  const cpes = data.cpes || []
  const tags = data.tags || []
  const vulns = data.vulns || []

  return (
    <div className="space-y-5 font-semibold">
      <RetriedNotice data={data} />
      {data.ip && (
        <div className="mono text-[10px] text-slate-500 font-bold">
          Queried IP: <span className="text-slate-800 bg-slate-50 border border-slate-200 rounded px-2 py-0.5">{data.ip}</span>
        </div>
      )}

      <div className="flex items-baseline gap-2">
        <div className={`mono text-4xl font-extrabold ${vulns.length > 0 ? 'text-red-600' : 'text-teal-700'}`}>
          {vulns.length}
        </div>
        <div className="mono text-[9px] text-slate-400 uppercase tracking-wider font-bold">known CVEs on detected services</div>
      </div>

      <div>
        <div className="mono text-[9px] text-slate-400 tracking-widest uppercase font-bold mb-2">
          Threat/Infra Tags ({tags.length})
        </div>
        {tags.length > 0 ? (
          <div className="space-y-1.5">
            {tags.map((t) => (
              <div key={t.tag} className="flex flex-wrap items-baseline gap-2">
                <span className="mono text-[10px] px-2.5 py-1 bg-indigo-50 border border-indigo-200 rounded text-indigo-700 font-bold uppercase shrink-0">
                  {t.tag}
                </span>
                {t.description && (
                  <span className="mono text-[10px] text-slate-500 font-semibold">{t.description}</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="mono text-xs text-slate-400 italic">None assigned.</div>
        )}
      </div>

      <div>
        <div className="mono text-[9px] text-slate-400 tracking-widest uppercase font-bold mb-2">
          Open Ports ({ports.length})
        </div>
        {ports.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {ports.map((p) => (
              <span key={p.port} className="mono text-[10px] px-2.5 py-1 bg-slate-50 border border-slate-200 rounded text-slate-800 font-bold">
                {p.port}{p.service ? ` · ${p.service}` : ''}
              </span>
            ))}
          </div>
        ) : (
          <div className="mono text-xs text-slate-400 italic">No open ports on record.</div>
        )}
      </div>

      <div>
        <div className="mono text-[9px] text-slate-400 tracking-widest uppercase font-bold mb-2">
          Associated Hostnames ({hostnames.length})
        </div>
        {hostnames.length > 0 ? (
          <div className="mono text-xs space-y-1 max-h-32 overflow-y-auto">
            {hostnames.map((h) => (
              <div key={h} className="text-slate-700 bg-white border border-slate-250 px-3 py-1.5 rounded font-bold shadow-sm break-all">{h}</div>
            ))}
          </div>
        ) : (
          <div className="mono text-xs text-slate-400 italic">None on record.</div>
        )}
      </div>

      <div>
        <div className="mono text-[9px] text-slate-400 tracking-widest uppercase font-bold mb-2">
          Detected Software ({cpes.length})
        </div>
        {cpes.length > 0 ? (
          <div className="mono text-xs space-y-1 max-h-32 overflow-y-auto">
            {cpes.map((c) => (
              <div key={c.raw} className="text-slate-700 bg-white border border-slate-250 px-3 py-1.5 rounded font-bold shadow-sm break-all">
                {c.vendor || c.product ? (
                  <>
                    <span className="text-slate-900">{[c.vendor, c.product].filter(Boolean).join(' ').replace(/_/g, ' ')}</span>
                    {c.version && <span className="text-slate-500 font-normal ml-1.5">v{c.version}</span>}
                    {c.type && <span className="text-slate-400 font-normal text-[10px] ml-1.5">({c.type})</span>}
                  </>
                ) : c.raw}
              </div>
            ))}
          </div>
        ) : (
          <div className="mono text-xs text-slate-400 italic">No software/version fingerprinted.</div>
        )}
      </div>

      <div className="pt-4 border-t border-slate-100">
        <div className={`mono text-[9px] tracking-widest uppercase font-bold mb-2 ${vulns.length > 0 ? 'text-red-600' : 'text-slate-400'}`}>
          Known Vulnerabilities ({vulns.length})
        </div>
        {vulns.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto p-1">
            {vulns.map((v) => (
              <a
                key={v}
                href={`https://nvd.nist.gov/vuln/detail/${v}`}
                target="_blank"
                rel="noopener noreferrer"
                className="mono text-[10px] px-2.5 py-1 bg-red-50 border border-red-200 rounded text-red-700 font-bold hover:bg-red-100 hover:border-red-300 transition"
              >
                {v}
              </a>
            ))}
          </div>
        ) : (
          <div className="mono text-xs text-slate-400 italic">No known CVEs tied to detected services.</div>
        )}
      </div>
    </div>
  )
}

export function HttpAvailabilitySection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No accessibility data available.</div>

  const OVERALL_STYLES = {
    https_ok: { label: 'Accessible (HTTPS)', color: 'text-teal-700 bg-teal-50 border-teal-200' },
    no_forced_https: { label: 'Accessible — HTTPS Not Enforced', color: 'text-amber-700 bg-amber-50 border-amber-200' },
    http_only: { label: 'HTTP Only — HTTPS Unavailable', color: 'text-amber-700 bg-amber-50 border-amber-200' },
    not_accessible: { label: 'Not Accessible', color: 'text-red-700 bg-red-50 border-red-200' },
    blocked_by_waf: { label: 'Blocked by WAF/Bot Protection', color: 'text-amber-700 bg-amber-50 border-amber-200' },
  }
  const overallStyle = OVERALL_STYLES[data.overall] || { label: data.overall || 'Unknown', color: 'text-slate-700 bg-slate-50 border-slate-200' }

  const PORT_STATE_ICONS = { open: Unlock, closed: Lock, filtered: ShieldAlert, unknown: HelpCircle }
  const PORT_STATE_STYLES = {
    open: 'bg-teal-50 text-teal-600 border border-teal-200',
    closed: 'bg-slate-100 text-slate-500 border border-slate-250',
    filtered: 'bg-amber-50 text-amber-600 border border-amber-200',
    unknown: 'bg-slate-100 text-slate-400 border border-slate-200',
  }

  const PortCard = ({ label, result }) => {
    if (!result) return null
    const badgeLabel = result.blocked_by_waf
      ? 'WAF Challenge'
      : result.weak_tls_downgrade
        ? 'Accessible (Weak TLS)'
        : result.accessible ? 'Accessible' : 'Not Accessible'
    const badgeColor = result.blocked_by_waf || result.weak_tls_downgrade
      ? 'bg-amber-50 text-amber-700 border border-amber-200'
      : result.accessible
        ? 'bg-teal-50 text-teal-700 border border-teal-200'
        : 'bg-red-50 text-red-700 border border-red-200'
    const StateIcon = PORT_STATE_ICONS[result.port_state] || HelpCircle
    const portStatusRow = result.port_state && (
      <div className="flex items-center justify-between border-b border-slate-100 py-2.5 font-semibold">
        <span className="text-[9.5px] text-slate-450 uppercase tracking-wider font-bold pr-4 shrink-0">Port Status</span>
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[10px] font-extrabold uppercase tracking-wide ${PORT_STATE_STYLES[result.port_state] || PORT_STATE_STYLES.unknown}`}>
          <StateIcon className="w-3 h-3" strokeWidth={2.5} />
          {result.port_state}
        </span>
      </div>
    )
    return (
      <div className="border border-slate-200 rounded-xl p-4 bg-white shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-[10px] text-slate-500 uppercase tracking-widest font-bold">{label} · Port {result.port}</span>
          <span className={`mono text-[9px] font-extrabold uppercase tracking-wide px-2 py-1 rounded-full ${badgeColor}`}>
            {badgeLabel}
          </span>
        </div>
        {result.blocked_by_waf && (
          <div className="mono text-xs text-amber-800 font-semibold bg-amber-50/40 border border-amber-100 rounded-lg px-3 py-2 mb-2">
            {result.waf_note}
          </div>
        )}
        {result.weak_tls_downgrade && (
          <div className="mono text-xs text-amber-800 font-semibold bg-amber-50/40 border border-amber-100 rounded-lg px-3 py-2 mb-2">
            {result.weak_tls_note}
          </div>
        )}
        {result.accessible ? (
          <div className="space-y-1.5">
            {portStatusRow}
            <KVGrid
              singleColumn
              pairs={[
                ['Status Code', result.status_code],
                ['HTTP Version', result.http_version],
                ['Response Time', `${result.response_time_ms}ms`],
                ['Redirects To', result.redirects_to],
                ['Redirect Hops', result.redirect_count > 0 ? result.redirect_count : null],
                ['Final URL', result.final_url],
                ['Final Status', result.final_status_code],
              ]}
            />
            <div className="flex flex-wrap gap-1.5 mt-1">
              {result.weak_tls_downgrade && (
                <span
                  title={result.weak_tls_note}
                  className="mono text-[9px] font-bold px-2 py-1 bg-amber-50 border border-amber-200 rounded text-amber-700 uppercase inline-block cursor-help"
                >
                  Weak TLS — Non-Standard Client Only
                </span>
              )}
              {result.http2_supported && (
                <span className="mono text-[9px] font-bold px-2 py-1 bg-indigo-50 border border-indigo-200 rounded text-indigo-700 uppercase inline-block">
                  HTTP/2 Supported (via ALPN)
                </span>
              )}
              {result.hsts && (
                <span
                  title={result.hsts.raw}
                  className="mono text-[9px] font-bold px-2 py-1 bg-teal-50 border border-teal-200 rounded text-teal-700 uppercase inline-block cursor-help"
                >
                  HSTS: max-age={result.hsts.max_age_seconds ?? '?'}
                  {result.hsts.include_subdomains ? ' · subdomains' : ''}
                  {result.hsts.preload ? ' · preload' : ''}
                </span>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-1.5">
            {portStatusRow}
            <div className="mono text-xs text-red-600 font-semibold bg-red-50/40 border border-red-100 rounded-lg px-3 py-2">
              {result.error_message || 'Connection failed.'}
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-4 font-semibold">
      <div className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border ${overallStyle.color}`}>
        <span className="mono text-xs font-extrabold uppercase tracking-wide">{overallStyle.label}</span>
      </div>
      {data.summary && (
        <p className="mono text-xs text-slate-600 font-semibold leading-relaxed">{data.summary}</p>
      )}
      <div className="space-y-4">
        <PortCard label="HTTP" result={data.http} />
        <PortCard label="HTTPS" result={data.https} />
      </div>
    </div>
  )
}

export function PortsSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No ports scanner information.</div>
  const openPorts = data.open_ports || []
  return (
    <div className="space-y-4">
      <div className="mono text-[10px] text-slate-450 uppercase tracking-wider border-b border-indigo-150 pb-3 font-bold flex flex-wrap gap-4">
        <span>Scanned: <span className="text-slate-900">{data.scanned_port_count}</span></span>
        <span>Open: <span className="text-teal-650 text-teal-600 font-bold">{data.open_port_count || 0}</span></span>
        <span>Closed: <span className="text-slate-500">{data.closed_port_count || 0}</span></span>
        <span>Filtered: <span className="text-amber-600">{data.filtered_port_count || 0}</span></span>
      </div>
      {data.reachability && data.reachability.reachable === false && (
        <div className="mono text-xs text-amber-650 bg-amber-50 border border-amber-200 rounded-lg p-3">
          {data.reachability.note}
        </div>
      )}
      {openPorts.length === 0 && (
        <div className="mono text-xs text-slate-400 py-3 text-center">
          No active listening services detected.
        </div>
      )}
      <div className="space-y-2.5">
        {openPorts.map((p) => (
          <div key={p.port} className="border border-indigo-100 bg-indigo-50/20 rounded-xl p-3.5 shadow-sm font-semibold">
            <div className="flex items-center gap-3.5 flex-wrap">
              <span className="mono text-base font-bold text-indigo-650 text-indigo-600 w-12">{p.port}</span>
              <span className="mono text-[9px] bg-indigo-100 border border-indigo-150 text-indigo-600 px-2 py-0.5 rounded uppercase tracking-wider font-semibold animate-pulse">tcp</span>
              <span className="mono text-xs text-slate-700 font-semibold">{p.service}</span>

              {p.version && (
                <span className="mono text-[9.5px] bg-white border border-indigo-200 text-indigo-650 px-2 py-0.5 rounded font-bold shadow-sm">
                  version: {p.version}
                </span>
              )}

              <span className="mono text-[10px] text-teal-655 text-teal-600 ml-auto font-bold uppercase tracking-wider">open</span>
            </div>
            {p.banner && (
              <div className="mono text-[11px] text-slate-600 mt-2.5 pt-2.5 border-t border-indigo-100 break-all leading-relaxed bg-white p-2 border rounded font-semibold shadow-inner">
                <span className="text-slate-400 text-[9px] uppercase font-bold mr-2">Service Header:</span> {p.banner}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export function TechSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No platform signatures identified.</div>

  const components = data.detected_components || []
  const techs = data.technologies || {}

  if (components.length === 0 && Object.keys(techs).length === 0) {
    return <div className="mono text-xs text-slate-400 py-3 text-center">No platform signatures identified.</div>
  }

  const grouped = {}
  if (components.length > 0) {
    components.forEach((c) => {
      const catLabel = c.category_label || (c.category ? c.category.replace(/_/g, ' ').toUpperCase() : 'OTHER')
      if (!grouped[catLabel]) grouped[catLabel] = []
      grouped[catLabel].push(c)
    })
  } else {
    Object.entries(techs).forEach(([cat, list]) => {
      const catLabel = cat.replace(/_/g, ' ').toUpperCase()
      grouped[catLabel] = list.map((item) => {
        const parts = item.split(' v')
        return {
          name: parts[0],
          version: parts[1] || 'Unknown',
          description: '',
          matched_by: 'Signature Pattern'
        }
      })
    })
  }

  return (
    <div className="space-y-5">
      {Object.entries(grouped).map(([categoryLabel, items]) => (
        <div key={categoryLabel} className="border border-slate-200 bg-white rounded-2xl p-4.5 shadow-sm">
          <div className="mono text-xs text-amber-900 uppercase tracking-widest font-extrabold mb-3.5 flex items-center gap-2 pb-2.5 border-b border-slate-150">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            {categoryLabel}
            <span className="mono text-[10px] bg-amber-100 text-amber-800 px-2 py-0.5 rounded font-bold ml-auto">
              {items.length} detected
            </span>
          </div>

          <div className="space-y-3">
            {items.map((item, idx) => {
              const hasVersion = item.version && item.version !== 'Unknown'
              return (
                <div
                  key={(item.name || 'tech') + '-' + idx}
                  className="border border-slate-200 bg-slate-50/40 hover:bg-white transition-all rounded-xl p-3.5 flex flex-col gap-2 shadow-2xs"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="font-extrabold text-slate-900 text-sm tracking-tight">{item.name}</span>
                    {hasVersion ? (
                      <span className="mono text-[10.5px] px-2.5 py-0.5 bg-teal-600 text-white rounded-md font-black tracking-wide shadow-xs">
                        v{item.version}
                      </span>
                    ) : (
                      <span className="mono text-[10px] px-2 py-0.5 bg-slate-200 text-slate-600 rounded-md font-semibold">
                        Version Unknown
                      </span>
                    )}
                  </div>

                  {item.description && (
                    <p className="text-xs text-slate-600 font-normal leading-relaxed">
                      {item.description}
                    </p>
                  )}

                  {item.matched_by && (
                    <div className="text-[11px] font-mono text-slate-600 flex flex-col sm:flex-row sm:items-center gap-2 pt-1 border-t border-slate-200/60 mt-1">
                      <span className="text-slate-400 font-bold uppercase text-[9px] shrink-0">Evidence:</span>
                      <span className="bg-amber-50/70 text-amber-950 px-2.5 py-1 rounded-md border border-amber-200/70 font-semibold break-all w-full">
                        {item.matched_by}
                      </span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

export function HeadersSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No headers data available.</div>
  const present = data.security_headers_present || {}
  const missing = data.security_headers_missing || []

  return (
    <div className="space-y-6">
      <div className="bg-cyan-50/30 border border-cyan-150 rounded-xl p-4 mono text-xs">
        <div className="flex flex-col gap-2 text-cyan-950">
          <div className="flex items-center justify-between border-b border-cyan-100 pb-2">
            <span className="text-cyan-700 font-bold text-[9.5px] uppercase tracking-wider">Resolved Destination</span>
            <span className="text-cyan-900 font-bold truncate max-w-sm" title={data.url}>{data.url}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-cyan-700 font-bold text-[9.5px] uppercase tracking-wider">Status Response</span>
            <span className="text-cyan-900 font-bold">{data.http_status} {data.reason}</span>
          </div>
          {data.was_redirected && data.redirect_history && (
            <div className="mt-3 pt-3 border-t border-cyan-150">
              <span className="text-cyan-800 text-[9px] uppercase font-bold tracking-widest block mb-2">Redirect Path:</span>
              <div className="space-y-1.5 pl-2 border-l border-cyan-500/30">
                {data.redirect_history.map((step, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-[11px] text-cyan-800">
                    <span className="text-[9px] bg-cyan-50 text-cyan-700 px-1 border border-cyan-200 rounded font-bold">{idx + 1}</span>
                    <span className="truncate max-w-xs md:max-w-md font-semibold">{step}</span>
                  </div>
                ))}
                <div className="flex items-center gap-2 text-[11px] text-teal-650 text-teal-600 font-bold">
                  <ArrowRight className="w-3.5 h-3.5 text-teal-505 text-teal-500" />
                  <span className="truncate max-w-xs md:max-w-md">{data.url}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div>
        <div className="mono text-[10px] text-cyan-800 uppercase tracking-widest font-bold mb-3">
          Configured Security Headers ({Object.keys(present).length})
        </div>
        {Object.keys(present).length === 0 ? (
          <div className="mono text-xs text-cyan-500 bg-white/70 border border-cyan-200 p-3 rounded-xl text-center font-bold">
            No active security headers detected.
          </div>
        ) : (
          <div className="space-y-3">
            {Object.entries(present).map(([name, val]) => {
              const misconfig = getHeaderMisconfigWarning(name, val)
              const idealConfig = HEADER_IDEAL_CONFIGS[name] || HEADER_IDEAL_CONFIGS[name.toLowerCase()]
              return (
                <div key={name} className="border border-cyan-150 bg-white/75 rounded-xl p-4 shadow-sm space-y-2">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-1 mb-1">
                    <span className="mono text-xs font-bold text-teal-700 uppercase">{name}</span>
                    <div className="flex items-center gap-1.5">
                      {misconfig ? (
                        <span className={`mono text-[9px] px-2 py-0.5 rounded font-bold tracking-wider uppercase inline-block ${misconfig.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border border-red-200' : 'bg-amber-50 text-amber-700 border border-amber-200'}`}>
                          {misconfig.severity === 'CRITICAL' ? 'MISCONFIGURED' : 'SUB-OPTIMAL'}
                        </span>
                      ) : (
                        <span className="mono text-[9px] px-2 py-0.5 bg-teal-50 border border-teal-200 rounded text-teal-750 text-teal-700 font-bold tracking-wider uppercase inline-block">Active</span>
                      )}
                    </div>
                  </div>
                  <div className="mono text-xs text-cyan-950 bg-white px-3 py-2 border border-cyan-150 rounded break-all leading-relaxed shadow-sm font-bold">
                    {val}
                  </div>
                  {misconfig && (
                    <div className="text-[11px] font-bold text-amber-800 bg-amber-50/80 border border-amber-200/80 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
                      <span className="font-extrabold uppercase text-[9px] tracking-wider text-amber-900 shrink-0">Config Audit:</span>
                      <span>{misconfig.text}</span>
                    </div>
                  )}
                  <div className="text-[11px] text-cyan-800 font-semibold italic leading-relaxed">
                    {HEADER_DESCRIPTIONS[name] || ''}
                  </div>
                  {idealConfig && (
                    <div className="text-[11px] font-bold text-emerald-800 bg-emerald-50/80 border border-emerald-200/80 px-3 py-1.5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <span className="font-extrabold uppercase text-[9px] tracking-wider text-emerald-900 shrink-0">Best Secure Configuration:</span>
                      <span className="mono text-[11px] text-emerald-950 font-bold break-all">{idealConfig}</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div>
        <div className="mono text-[10px] text-cyan-800 uppercase tracking-widest font-bold mb-3">
          Missing Recommendations ({missing.length})
        </div>
        {missing.length === 0 ? (
          <div className="mono text-xs text-teal-700 bg-teal-50 border border-teal-200 p-3 rounded-xl text-center glow-emerald font-bold">
            Perfect! All scanned security headers are present.
          </div>
        ) : (
          <div className="space-y-3">
            {missing.map((name) => {
              const idealConfig = HEADER_IDEAL_CONFIGS[name] || HEADER_IDEAL_CONFIGS[name.toLowerCase()]
              return (
                <div key={name} className="border border-cyan-200 bg-white/70 rounded-xl p-4 shadow-sm space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="mono text-xs font-bold text-slate-500 uppercase">{name}</span>
                    <span className="mono text-[9px] px-1.5 py-0.5 bg-red-50 border border-red-200 rounded text-red-750 text-red-700 font-bold uppercase tracking-wider animate-pulse">Missing</span>
                  </div>
                  <p className="text-[11px] text-cyan-800/80 leading-relaxed font-semibold">
                    {HEADER_DESCRIPTIONS[name] || 'Recommended security configuration.'}
                  </p>
                  {idealConfig && (
                    <div className="text-[11px] font-bold text-emerald-800 bg-emerald-50/80 border border-emerald-200/80 px-3 py-1.5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <span className="font-extrabold uppercase text-[9px] tracking-wider text-emerald-900 shrink-0">Best Secure Configuration:</span>
                      <span className="mono text-[11px] text-emerald-950 font-bold break-all">{idealConfig}</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div>
        <div className="mono text-[10px] text-cyan-800 uppercase tracking-widest font-bold mb-2">
          Raw Response Headers
        </div>
        <div className="mono text-xs bg-white border border-cyan-200 rounded-xl p-4 max-h-72 overflow-y-auto leading-relaxed shadow-inner">
          {Object.entries(data.all_headers || {}).map(([k, v]) => (
            <div key={k} className="py-1 border-b border-cyan-100 break-all flex flex-col md:flex-row md:items-start font-bold">
              <span className="text-teal-700 md:w-56 flex-shrink-0">{k}</span>
              <span className="text-cyan-950 mt-0.5 md:mt-0">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export function SubdomainsSection({ data, searchQuery, setSearchQuery, filter, setFilter }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center">No subdomains data.</div>
  const list = data.subdomains || []

  const filteredList = list.filter((s) => {
    const matchesSearch = s.subdomain.toLowerCase().includes(searchQuery.toLowerCase()) || (s.ip && s.ip.includes(searchQuery))
    const matchesFilter = filter === 'all' ? true : (filter === 'resolved' ? !!s.ip : !s.ip)
    return matchesSearch && matchesFilter
  })

  return (
    <div className="space-y-4">
      {data.sources && (
        <div className="flex flex-col gap-2 border-b border-purple-150 pb-3.5">
          <div className="mono text-[10px] text-purple-800 flex flex-wrap gap-x-4 gap-y-1.5 uppercase tracking-wider font-bold">
            {Object.entries(data.sources).map(([name, meta]) => {
              const count = meta.count || 0
              const status = meta.status
              if (status === 'not_installed') {
                return (
                  <span key={name} className="flex items-center gap-1.5 bg-white/70 px-2.5 py-1 rounded border border-purple-200 text-purple-400 font-bold" title={`${name} is not installed`}>
                    <span>{name}:</span>
                    <span className="text-[10px] text-purple-500 font-bold lowercase tracking-normal">(not installed)</span>
                  </span>
                )
              }
              return (
                <span key={name} className="flex items-center gap-1.5 bg-white/75 px-2.5 py-1 rounded border border-purple-200 text-purple-955 font-bold">
                  <span>{name}:</span>
                  <span className={count > 0 ? 'text-teal-605 text-teal-600 font-bold' : 'text-purple-400'}>{count}</span>
                </span>
              )
            })}
          </div>
          <div className="mono text-[10px] text-slate-500 font-semibold italic">
            * Note: Discovered {Object.values(data.sources).reduce((acc, curr) => acc + (curr.count || 0), 0)} raw subdomain matches in total across all sources. These have been merged and deduplicated into {list.length} unique subdomains below.
          </div>
        </div>
      )}

      <div className="flex flex-col md:flex-row gap-3 bg-white/85 p-3 border border-purple-150 rounded-xl shadow-sm">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-purple-450" />
          <input
            type="text"
            placeholder="Search subdomains or IPs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-white border border-purple-200 rounded-lg text-xs font-mono text-purple-955 placeholder-purple-305 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/10 font-bold"
          />
        </div>
        <div className="flex gap-1.5">
          <button
            onClick={() => setFilter('all')}
            className={`px-3.5 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider border transition-all ${filter === 'all'
              ? 'bg-purple-600 text-white border-purple-600 shadow-sm'
              : 'bg-white border-purple-200 text-purple-750 hover:bg-purple-50'
              }`}
          >
            Show All ({list.length})
          </button>
          <button
            onClick={() => setFilter('resolved')}
            className={`px-3.5 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider border transition-all ${filter === 'resolved'
              ? 'bg-purple-600 text-white border-purple-600 shadow-sm'
              : 'bg-white border-purple-200 text-purple-750 hover:bg-purple-50'
              }`}
          >
            Resolved Only ({list.filter(s => s.ip).length})
          </button>
        </div>
      </div>

      <div className="mono text-xs bg-white border border-purple-200 rounded-xl overflow-hidden max-h-[25rem] overflow-y-auto shadow-sm">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-purple-50 border-b border-purple-150 z-10">
            <tr className="text-[9px] uppercase tracking-widest text-purple-750 font-bold">
              <th className="px-4 py-3">Subdomain</th>
              <th className="px-4 py-3">Resolved IP</th>
              <th className="px-4 py-3">Source Provider</th>
            </tr>
          </thead>
          <tbody>
            {filteredList.map((s, idx) => (
              <tr key={s.subdomain + '-' + idx} className="border-b border-purple-50 hover:bg-purple-50/30 transition">
                <td className="px-4 py-2.5 text-purple-955 break-all select-all font-mono font-bold">{s.subdomain}</td>
                <td className="px-4 py-2.5 font-mono">
                  {s.ip ? (
                    <span className="text-teal-600 font-bold">{s.ip}</span>
                  ) : (
                    <span className="text-purple-400">—</span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-purple-700/80 text-[10px] uppercase font-bold">{s.source}</td>
              </tr>
            ))}
            {filteredList.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-6 text-center text-purple-400 font-mono text-xs font-bold">
                  No subdomain match discovered for the active filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export function DirectoriesSection({ data, filter, setFilter }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No directories discovery details.</div>
  const paths = data.found || []

  const filteredPaths = paths.filter((p) => {
    if (filter === 'all') return true
    if (filter === '200') return p.status === 200
    if (filter === '403') return p.status === 403 || p.status === 401
    return p.status !== 200 && p.status !== 403 && p.status !== 401
  })

  const statusColor = (s) => {
    if (s === 200) return 'text-teal-800 bg-teal-50 border-teal-200 font-bold shadow-sm'
    if (s === 401 || s === 403) return 'text-amber-800 bg-amber-50 border-amber-200 font-bold shadow-sm'
    if (s >= 300 && s < 400) return 'text-cyan-800 bg-cyan-50 border-cyan-200 font-bold shadow-sm'
    return 'text-teal-900/60 bg-teal-50/50 border-teal-150 font-bold'
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5 bg-white/70 p-2.5 border border-teal-150 rounded-xl shadow-sm">
        <button
          onClick={() => setFilter('all')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border transition-all ${filter === 'all'
            ? 'bg-teal-605 bg-teal-600 text-white border-teal-600 shadow-sm'
            : 'bg-white border-teal-200 text-teal-700 hover:bg-teal-50'
            }`}
        >
          Show All ({paths.length})
        </button>
        <button
          onClick={() => setFilter('200')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border transition-all ${filter === '200'
            ? 'bg-teal-605 bg-teal-600 text-white border-teal-600 shadow-sm'
            : 'bg-white border-teal-200 text-teal-700 hover:bg-teal-50'
            }`}
        >
          200 OK Only ({paths.filter(p => p.status === 200).length})
        </button>
        <button
          onClick={() => setFilter('403')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border transition-all ${filter === '403'
            ? 'bg-teal-605 bg-teal-600 text-white border-teal-600 shadow-sm'
            : 'bg-white border-teal-200 text-teal-700 hover:bg-teal-50'
            }`}
        >
          Auth/Forbidden Only ({paths.filter(p => p.status === 403 || p.status === 401).length})
        </button>
      </div>

      <div className="mono text-xs space-y-2 max-h-[25rem] overflow-y-auto pr-1">
        {filteredPaths.map((p) => (
          <div key={p.path} className="flex items-center gap-3.5 bg-white border border-teal-150 rounded-xl px-4 py-3.5 shadow-sm font-semibold">
            <span className={`px-2.5 py-0.5 border rounded text-[11px] font-mono w-14 text-center ${statusColor(p.status)}`}>
              {p.status}
            </span>
            <div className="flex-1 flex flex-col min-w-0">
              <span className="text-teal-950 break-all select-all font-mono font-bold">{p.path}</span>
              {p.url && (
                <a href={p.url} target="_blank" rel="noopener noreferrer" className="text-teal-600 text-[10px] hover:underline font-mono break-all mt-0.5">
                  {p.url}
                </a>
              )}
            </div>
            {p.content_type && (
              <span className="text-teal-700/70 text-[10px] font-bold uppercase tracking-wider whitespace-nowrap">{p.content_type}</span>
            )}
          </div>
        ))}
        {filteredPaths.length === 0 && (
          <div className="mono text-xs text-teal-605 py-6 border border-teal-200 rounded-xl text-center bg-white font-bold">
            No diagnostic paths match the selected status code filters.
          </div>
        )}
      </div>
    </div>
  )
}

function formatDate(dateStr) {
  if (!dateStr) return '—'
  try {
    if (Array.isArray(dateStr)) dateStr = dateStr[0]
    const d = new Date(dateStr)
    return d.toISOString().split('T')[0]
  } catch (e) {
    return dateStr
  }
}

export function ReverseDnsSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No Reverse DNS Pointer data available.</div>
  if (data.status === 'error' || data.status === 'timeout') {
    return <ModuleStatus data={data} moduleName="Reverse DNS" />
  }
  return (
    <div className="mono text-xs bg-slate-50 border border-slate-200 px-4 py-3.5 rounded-xl text-slate-800 font-semibold">
      <RetriedNotice data={data} />
      <div className="font-semibold text-slate-900 select-all font-mono font-bold">{data.hostname || 'No PTR record found'}</div>
      {data.nslookup_resolver_hostname && data.nslookup_resolver_hostname !== data.hostname && (
        <div className="text-[10px] text-slate-500 mt-1.5 font-bold">
          Comparing resolvers: Socket resolution resolved <span className="font-mono font-medium text-slate-700">{data.primary_resolver_hostname || '—'}</span>, nslookup resolved <span className="font-mono font-medium text-slate-700">{data.nslookup_resolver_hostname}</span>
        </div>
      )}
    </div>
  )
}

export function CloudProviderSection({ data, r }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No cloud provider data available.</div>
  if (data.status === 'error' || data.status === 'timeout') {
    return <ModuleStatus data={data} moduleName="Cloud Provider" />
  }

  const providerColors = {
    'AWS': 'bg-orange-100 text-orange-800 border-orange-200',
    'Google Cloud': 'bg-blue-100 text-blue-800 border-blue-200',
    'Azure': 'bg-cyan-100 text-cyan-800 border-cyan-200',
    'Cloudflare': 'bg-amber-100 text-amber-800 border-amber-200',
    'DigitalOcean': 'bg-blue-100 text-blue-800 border-blue-200',
    'Linode/Akamai': 'bg-green-100 text-green-800 border-green-200',
    'Hetzner': 'bg-red-100 text-red-800 border-red-200',
    'OVH': 'bg-indigo-100 text-indigo-800 border-indigo-200',
    'Oracle Cloud': 'bg-red-100 text-red-800 border-red-200',
    'Vultr': 'bg-sky-100 text-sky-800 border-sky-200',
  }

  const badgeColor = data.provider ? (providerColors[data.provider] || 'bg-slate-100 text-slate-800 border-slate-200') : 'bg-slate-100 text-slate-600 border-slate-200'

  const geo = r?.geo_ip || {}
  const asnOrg = data.asn_org || geo.organization || geo.org || '—'
  const ispProvider = data.asn_isp || geo.isp || '—'
  const asnNumber = data.as_number || geo.asn || (typeof geo.organization === 'string' ? geo.organization.match(/AS\d+/i)?.[0] : null) || '—'
  const hostingStatus = data.is_hosting !== undefined ? (data.is_hosting ? 'Yes (Cloud/Datacenter)' : 'No (Residential/Business)') : (geo.is_hosting ? 'Yes (Datacenter)' : 'Datacenter / Public Cloud')
  const location = geo.country ? `${geo.country}${geo.city ? `, ${geo.city}` : ''}` : '—'

  const fields = [
    ['Detected Cloud Vendor', data.cloud_detected ? data.provider : 'Self-Hosted / Non-Cloud'],
    ['Target IP Address', data.ip || geo.ip || 'N/A'],
    ['Detection Method', data.method ? data.method.replace(/_/g, ' ') : 'CIDR Range Match'],
    ['ASN Organization', asnOrg],
    ['ISP Provider', ispProvider],
    ['AS Number', asnNumber],
    ['Datacenter Location', location],
    ['Hosting Server', hostingStatus],
    ['CIDR Subnets Probed', data.ranges_checked !== undefined ? `${data.ranges_checked.toLocaleString()} ranges` : '—'],
    ['Cloud Engines Audited', Array.isArray(data.providers_checked) ? data.providers_checked.map(p => p.replace(/\s*\(fetch failed or empty\)/g, '')).join(', ') : 'AWS, GCP, Azure, Cloudflare, DigitalOcean, Oracle, Linode, Vultr, Fastly']
  ]

  return (
    <div className="space-y-4">
      <RetriedNotice data={data} />
      <div className="flex items-center gap-3">
        <div className={`px-4 py-2 rounded-xl border text-sm font-extrabold shadow-sm ${badgeColor}`}>
          ☁️ {data.cloud_detected ? data.provider : 'Self-Hosted / Non-Cloud'}
        </div>
        {data.confidence && (
          <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider border shadow-sm ${
            data.confidence === 'high' ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : data.confidence === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-200'
                : 'bg-slate-50 text-slate-600 border-slate-200'
          }`}>
            {data.confidence} confidence
          </span>
        )}
      </div>

      <KVGrid pairs={fields} singleColumn={true} />

      {!data.cloud_detected && (
        <div className="text-[10px] text-slate-500 font-semibold bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2.5 leading-relaxed">
          Target IP does not fall within any known public cloud provider's published IP ranges (AWS, GCP, Azure, Cloudflare, etc.). The server is likely self-hosted, on a dedicated server, or using an on-premise infrastructure.
        </div>
      )}
    </div>
  )
}

export function WafDetectionSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No WAF detection data available.</div>
  if (data.status === 'error' || data.status === 'timeout') {
    return <ModuleStatus data={data} moduleName="WAF Detection" />
  }

  const isMultiple = data.all_detected && data.all_detected.length > 1;
  const primaryWaf = data.waf_name || 'WAF Detected';

  return (
    <div className="space-y-6">
      <div className={`p-4 rounded-xl border ${data.waf_detected
        ? 'bg-red-50/50 border-red-200'
        : 'bg-emerald-50/50 border-emerald-200'
        }`}>
        <div className="flex items-start gap-4">
          <div className={`p-2.5 rounded-lg shrink-0 ${data.waf_detected ? 'bg-red-100 text-red-600' : 'bg-emerald-100 text-emerald-600'
            }`}>
            {data.waf_detected ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
          </div>
          <div className="flex-1 pt-0.5">
            <h3 className={`text-lg font-black ${data.waf_detected ? 'text-red-900' : 'text-emerald-900'
              }`}>
              {data.waf_detected ? (isMultiple ? 'Multiple WAF Layers Detected' : primaryWaf) : 'No WAF Detected'}
            </h3>
            <p className={`text-[11px] font-medium leading-relaxed mt-1 pr-2 ${data.waf_detected ? 'text-red-700/80' : 'text-emerald-700/80'
              }`}>
              {data.waf_detected
                ? (isMultiple
                  ? `The scanner identified signatures for ${data.all_detected.join(', ')}. The primary active defense appears to be ${primaryWaf}.`
                  : `The target is actively protected by ${primaryWaf}. The WAF is blocking attack signatures.`)
                : 'No Web Application Firewall signatures were detected. The target allowed attack probes through without blocking.'}
            </p>
          </div>
          {data.confidence && data.waf_detected && (
            <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider border shrink-0 mt-1 ${data.confidence === 'high' ? 'bg-red-100 text-red-700 border-red-200'
              : data.confidence === 'medium' ? 'bg-amber-100 text-amber-700 border-amber-200'
                : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
              {data.confidence} confidence
            </span>
          )}
        </div>
      </div>

      {data.detections && data.detections.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
            <Search className="w-4 h-4 text-slate-400" />
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Signature Evidence</h4>
          </div>
          <div className="grid gap-3">
            {data.detections.map((det, i) => {
              const isPrimary = det.waf_name === primaryWaf;
              return (
                <div key={i} className={`rounded-xl px-4 py-3 border ${isPrimary ? 'bg-white border-red-200 shadow-sm' : 'bg-slate-50 border-slate-200'
                  }`}>
                  <div className="flex items-center gap-3 mb-2.5">
                    <div className={`text-xs font-bold ${isPrimary ? 'text-red-800' : 'text-slate-700'}`}>
                      {det.waf_name}
                    </div>
                    {isPrimary && (
                      <span className="text-[9px] px-1.5 py-0.5 bg-red-100 text-red-600 rounded uppercase tracking-wider font-bold">Primary</span>
                    )}
                  </div>
                  <div className="space-y-1.5 bg-slate-50 border border-slate-100 p-2.5 rounded-lg">
                    {det.evidence.map((ev, j) => (
                      <div key={j} className="text-[11px] font-mono text-slate-600 flex items-start gap-2">
                        <span className={`w-1 h-1 rounded-full mt-1.5 shrink-0 ${isPrimary ? 'bg-red-400' : 'bg-slate-400'}`} />
                        <span className="break-all">{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {data.probes && data.probes.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
            <Activity className="w-4 h-4 text-slate-400" />
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Behavioral Probes</h4>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {data.probes.map((probe, i) => (
              <div key={i} className={`relative overflow-hidden rounded-xl p-3 border ${probe.likely_blocked ? 'bg-red-50/30 border-red-200' : 'bg-emerald-50/30 border-emerald-200'
                }`}>
                {probe.likely_blocked ? (
                  <div className="absolute top-0 left-0 w-1 h-full bg-red-500" />
                ) : (
                  <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500" />
                )}
                <div className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                  {probe.probe.replace(/_/g, ' ')}
                </div>
                <div className="flex items-end justify-between">
                  <span className={`text-xl font-black ${probe.likely_blocked ? 'text-red-700' : 'text-emerald-700'
                    }`}>
                    {probe.status_code}
                  </span>
                  <span className={`text-[9px] font-bold uppercase tracking-wider mb-1 ${probe.likely_blocked ? 'text-red-500' : 'text-emerald-600'
                    }`}>
                    {probe.likely_blocked ? 'Blocked' : 'Passed'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function CmsFingerprintSection({ data }) {
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No CMS fingerprint data available.</div>
  if (data.status === 'error' || data.status === 'timeout') {
    return <ModuleStatus data={data} moduleName="CMS Fingerprinting" />
  }

  const cmsChecked = ['WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify', 'Wix', 'Squarespace', 'Ghost', 'TYPO3', 'PrestaShop', 'Hugo', 'Gatsby', 'Next.js', 'Nuxt.js', 'Laravel']

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-sm font-extrabold ${data.cms_detected
          ? 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200'
          : 'bg-slate-50 text-slate-600 border-slate-200'
          }`}>
          <Fingerprint className="w-4 h-4" />
          {data.cms_detected ? data.cms_name : 'Custom / Non-CMS Site'}
          {data.version && <span className="text-fuchsia-500 font-mono text-xs ml-1">v{data.version}</span>}
        </div>
        {data.confidence && data.cms_detected && (
          <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider border ${data.confidence === 'high' ? 'bg-fuchsia-50 text-fuchsia-600 border-fuchsia-200'
            : data.confidence === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-200'
              : 'bg-slate-50 text-slate-600 border-slate-200'
            }`}>
            {data.confidence} confidence
          </span>
        )}
      </div>

      {data.generator_tag && (
        <div className="mono text-xs">
          <div className="flex justify-between border-b border-slate-100 pb-1.5">
            <span className="text-slate-400 font-bold uppercase text-[9px]">Meta Generator Tag</span>
            <span className="text-slate-700 font-bold font-mono">{data.generator_tag}</span>
          </div>
        </div>
      )}

      {data.all_detected && data.all_detected.length > 0 && (
        <div className="space-y-2">
          <div className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400">Detection Evidence</div>
          {data.all_detected.map((det, i) => (
            <div key={i} className="bg-slate-50 border border-slate-200 rounded-xl px-4 py-3">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-xs font-bold text-slate-800">{det.cms_name}</span>
                {det.version && <span className="text-[10px] font-mono text-fuchsia-600 bg-fuchsia-50 border border-fuchsia-200 px-1.5 py-0.5 rounded">v{det.version}</span>}
                <span className={`ml-auto px-2 py-0.5 rounded text-[9px] font-bold uppercase ${det.confidence === 'high' ? 'bg-emerald-50 text-emerald-700'
                  : det.confidence === 'medium' ? 'bg-amber-50 text-amber-700'
                    : 'bg-slate-100 text-slate-600'
                  }`}>{det.confidence}</span>
              </div>
              <ul className="space-y-1">
                {det.evidence.map((ev, j) => (
                  <li key={j} className="text-[11px] text-slate-600 font-mono flex items-start gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-fuchsia-400 mt-1.5 flex-shrink-0" />
                    {ev}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      <div className="space-y-2">
        <div className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400">Platforms Scanned</div>
        <div className="flex flex-wrap gap-1.5">
          {cmsChecked.map((cms, i) => {
            const found = data.all_detected?.some(d => d.cms_name === cms)
            return (
              <span key={i} className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${found ? 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200' : 'bg-slate-50 text-slate-400 border-slate-200'
                }`}>
                {found ? '✓' : '✗'} {cms}
              </span>
            )
          })}
        </div>
      </div>

      {!data.cms_detected && (
        <div className="text-[10px] text-slate-500 font-semibold bg-slate-50 border border-slate-200 rounded-lg px-3 py-2.5 leading-relaxed">
          No known CMS platform was detected. The site is likely built with a custom framework, static site generator, or the CMS fingerprints are deliberately hidden. This is generally a positive security indicator.
        </div>
      )}
    </div>
  )
}

export function EmailGatherSection({ data }) {
  const [filter, setFilter] = useState('all')
  if (!data) return <div className="mono text-xs text-slate-400 py-3 text-center font-bold">No email harvesting data available.</div>
  if (data.status === 'error' || data.status === 'timeout' || data.status === 'skipped') {
    return <ModuleStatus data={data} moduleName="Email Harvesting" />
  }

  const emails = data?.emails || []

  const SOURCE_COLORS = {
    crt_sh: '#3b82f6', pgp_keyserver: '#8b5cf6', ubuntu_pgp: '#a855f7', mit_pgp: '#6366f1',
    wayback_machine: '#f59e0b', wayback_docs: '#d97706', web_crawl: '#10b981', dns_txt_dmarc: '#06b6d4',
    subdomain_dns: '#0284c7', github_search: '#1d4ed8', bing_search: '#eab308', commoncrawl: '#7c3aed',
    alienvault_otx: '#ec4899', threatminer: '#ef4444', urlscan: '#f97316', certspotter: '#14b8a6',
    keybase: '#3b82f6', email_format: '#0284c7', skymem: '#6366f1', smtp_banner: '#64748b',
    ahmia_darkweb: '#dc2626', paste_dumps: '#ea580c', leakix: '#b91c1c', forum_registrations: '#4f46e5',
    gitlab_search: '#fc6d26', duckduckgo_search: '#de5833', qwant_search: '#0055ff',
    bitbucket_gitee: '#2563eb', cloud_storage_buckets: '#0284c7', database_backups: '#b91c1c'
  }
  const SOURCE_LABELS = {
    crt_sh: 'crt.sh', pgp_keyserver: 'OpenPGP', ubuntu_pgp: 'Ubuntu PGP', mit_pgp: 'MIT PGP',
    wayback_machine: 'Wayback', wayback_docs: 'Wayback Docs', web_crawl: 'Web Crawl', dns_txt_dmarc: 'DNS/DMARC',
    subdomain_dns: 'Subdomain DNS', github_search: 'GitHub', bing_search: 'Bing', commoncrawl: 'CommonCrawl',
    alienvault_otx: 'AlienVault OTX', threatminer: 'ThreatMiner', urlscan: 'URLScan', certspotter: 'CertSpotter',
    keybase: 'Keybase', email_format: 'Email-Format', skymem: 'Skymem', smtp_banner: 'SMTP Banner',
    ahmia_darkweb: 'Ahmia Darkweb', paste_dumps: 'Paste Dumps', leakix: 'LeakIX', forum_registrations: 'Forums & Events',
    gitlab_search: 'GitLab', duckduckgo_search: 'DuckDuckGo', qwant_search: 'Qwant',
    bitbucket_gitee: 'Bitbucket/Gitee', cloud_storage_buckets: 'Cloud Buckets', database_backups: 'DB Backups'
  }

  const employeeCount = data?.employee_accounts_count || emails.filter(e => e.account_type === 'employee').length
  const roleCount = data?.role_accounts_count || emails.filter(e => e.account_type === 'role').length
  const leakedCount = data?.leaked_accounts_count || emails.filter(e => e.is_leaked).length

  const filtered = emails.filter(e => {
    if (filter === 'employee') return e.account_type === 'employee'
    if (filter === 'role') return e.account_type === 'role'
    if (filter === 'leaked') return e.is_leaked
    return true
  })

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="border border-violet-100 rounded-xl p-3.5 bg-violet-50/60 text-center">
          <div className="text-[10px] font-extrabold uppercase tracking-widest text-violet-500 mb-1">Total Found</div>
          <div className="text-2xl font-black text-violet-700">{data?.total_found || emails.length}</div>
          <div className="text-[9px] text-violet-400 font-semibold mt-0.5">unique emails</div>
        </div>
        <div className="border border-blue-100 rounded-xl p-3.5 bg-blue-50/60 text-center">
          <div className="text-[10px] font-extrabold uppercase tracking-widest text-blue-600 mb-1">Employee Accounts</div>
          <div className="text-2xl font-black text-blue-700">{employeeCount}</div>
          <div className="text-[9px] text-blue-500 font-semibold mt-0.5">individual staff</div>
        </div>
        <div className="border border-teal-100 rounded-xl p-3.5 bg-teal-50/60 text-center">
          <div className="text-[10px] font-extrabold uppercase tracking-widest text-teal-600 mb-1">Role Accounts</div>
          <div className="text-2xl font-black text-teal-700">{roleCount}</div>
          <div className="text-[9px] text-teal-500 font-semibold mt-0.5">group / admin</div>
        </div>
        <div className="border border-rose-100 rounded-xl p-3.5 bg-rose-50/60 text-center">
          <div className="text-[10px] font-extrabold uppercase tracking-widest text-rose-600 mb-1">Leaked / Exposed</div>
          <div className="text-2xl font-black text-rose-700">{leakedCount}</div>
          <div className="text-[9px] text-rose-500 font-semibold mt-0.5">public leak exposure</div>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 bg-slate-50 p-2 border border-slate-200 rounded-xl">
        <button
          onClick={() => setFilter('all')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-extrabold uppercase tracking-wider transition-all ${
            filter === 'all' ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
          }`}
        >
          Show All ({emails.length})
        </button>
        <button
          onClick={() => setFilter('employee')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-extrabold uppercase tracking-wider transition-all ${
            filter === 'employee' ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
          }`}
        >
          Employee Accounts ({employeeCount})
        </button>
        <button
          onClick={() => setFilter('role')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-extrabold uppercase tracking-wider transition-all ${
            filter === 'role' ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
          }`}
        >
          Role Accounts ({roleCount})
        </button>
        <button
          onClick={() => setFilter('leaked')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-extrabold uppercase tracking-wider transition-all ${
            filter === 'leaked' ? 'bg-rose-600 text-white shadow-sm' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
          }`}
        >
          Exposed / Leaked ({leakedCount})
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="border border-slate-200 rounded-xl p-8 bg-slate-50 text-slate-400 text-center text-xs font-bold uppercase tracking-widest">
          No email addresses match the selected filter.
        </div>
      ) : (
        <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          <div className="grid grid-cols-12 bg-slate-100 px-4 py-2.5 text-[10px] font-extrabold uppercase tracking-widest text-slate-600 border-b border-slate-200">
            <div className="col-span-6">EMAIL ADDRESS</div>
            <div className="col-span-2 text-center">TYPE</div>
            <div className="col-span-4 text-right">SOURCES</div>
          </div>

          <div className="divide-y divide-slate-100 max-h-[30rem] overflow-y-auto">
            {filtered.map((e, i) => (
              <div key={i} className="grid grid-cols-12 items-center px-4 py-3 hover:bg-indigo-50/40 transition-colors">
                <div className="col-span-6 flex items-center gap-2 font-mono text-xs font-bold text-slate-900 break-all select-all">
                  <span className="text-slate-400 select-none">✉</span>
                  {e.email}
                </div>

                <div className="col-span-2 text-center flex items-center justify-center gap-1.5">
                  <span className={`text-[9px] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded-md ${
                    e.account_type === 'employee' ? 'bg-blue-100 text-blue-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {e.account_type === 'employee' ? 'Employee' : 'Role'}
                  </span>
                  {e.is_leaked && (
                    <span className="text-[9px] font-extrabold uppercase tracking-wider px-1.5 py-0.5 rounded-md bg-rose-100 text-rose-700">
                      Leaked
                    </span>
                  )}
                </div>

                <div className="col-span-4 flex flex-wrap justify-end gap-1.5">
                  {(e.sources || []).map(src => (
                    <span
                      key={src}
                      style={{
                        backgroundColor: (SOURCE_COLORS[src] || '#64748b') + '1a',
                        color: SOURCE_COLORS[src] || '#64748b',
                        borderColor: (SOURCE_COLORS[src] || '#64748b') + '33'
                      }}
                      className="text-[10px] font-bold px-2 py-0.5 rounded-md border"
                    >
                      {SOURCE_LABELS[src] || src}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


