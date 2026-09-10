
export const SCAN_REPORT_STYLES = `
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        * { box-sizing: border-box; }
        body {
            font-family: 'Outfit', system-ui, -apple-system, sans-serif;
            -webkit-font-smoothing: antialiased;
            line-height: 1.5;
            color: #0f172a;
            background: linear-gradient(to top right, #bae6fd, #e0f2fe, #ccfbf1);
            background-attachment: fixed;
            margin: 0;
            padding: 40px 20px;
        }
        h1, h2, h3, h4, h5, h6 { font-family: 'Outfit', system-ui, sans-serif; }
        .container {
            max-width: 1180px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #0d9488 0%, #06b6d4 100%);
            color: #ffffff;
            padding: 40px 35px;
            border-radius: 24px;
            margin-bottom: 32px;
            box-shadow: 0 20px 35px -5px rgba(13, 148, 136, 0.3), 0 10px 15px -3px rgba(13, 148, 136, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .header h1 {
            margin: 0 0 15px 0;
            font-size: 36px;
            font-weight: 900;
            letter-spacing: -0.8px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        .header .subtitle {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 3px;
            font-weight: 800;
            color: rgba(255, 255, 255, 0.85);
            margin-bottom: 25px;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            padding-top: 20px;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-item .label {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #ffedd5;
            font-weight: 700;
        }
        .meta-item .value {
            font-size: 16px;
            font-weight: 700;
            margin-top: 4px;
        }

        /* "Diagnostics Panel" target header — matches the app's own live panel */
        .target-panel {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 20px;
            padding: 24px 28px;
            margin-bottom: 28px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03), 0 10px 40px rgba(15, 23, 42, 0.04);
        }
        .target-panel-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #94a3b8;
            font-weight: 700;
            margin-bottom: 6px;
        }
        .target-panel-name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 22px;
            font-weight: 700;
            color: #0f172a;
            margin: 0 0 10px 0;
            word-break: break-all;
        }
        .target-panel-meta {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #64748b;
            font-weight: 600;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 12px;
        }
        .target-panel-meta .sep { color: #cbd5e1; }
        .target-panel-meta .mode-tag {
            color: #0d9488;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 20px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03), 0 10px 30px rgba(15, 23, 42, 0.04);
        }
        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #f1f5f9;
            margin: 0 0 20px 0;
            padding: 0 0 18px 0;
        }
        .card-title {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 800;
            margin: 0;
            color: #0f172a;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-badge {
            font-family: 'Outfit', sans-serif;
            font-size: 10px;
            font-weight: 800;
            padding: 5px 11px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
            border: 1px solid;
        }
        .status-badge.ok {
            background-color: #ecfdf5;
            color: #15803d;
            border-color: #a7f3d0;
        }
        .status-badge.skipped {
            background-color: #f8fafc;
            color: #64748b;
            border-color: #e2e8f0;
        }
        .status-badge.error {
            background-color: #fef2f2;
            color: #b91c1c;
            border-color: #fecaca;
        }
        .status-badge.partial {
            background-color: #fffbeb;
            color: #b45309;
            border-color: #fde68a;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #e2e8f0;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #f1f5f9;
            font-size: 13px;
        }
        th {
            background: #f8fafc;
            color: #64748b;
            font-weight: 800;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid #e2e8f0;
        }
        tbody tr:hover {
            background-color: #f8fafc;
        }
        .mono {
            font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace;
        }
        .tag {
            display: inline-block;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            color: #334155;
            padding: 4px 10px;
            border-radius: 999px;
            margin: 3px 3px;
        }
        .tag-teal {
            background-color: #f0fdfa;
            border-color: #99f6e4;
            color: #0f766e;
            font-weight: 900;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .kv-table {
            border: none;
            border-radius: 0;
        }
        .kv-table th {
            width: 32%;
            background: transparent;
            border-bottom: 1px solid #f1f5f9;
            color: #94a3b8;
            font-weight: 800;
            font-size: 10px;
            letter-spacing: 0.8px;
        }
        .kv-table td {
            border-bottom: 1px solid #f1f5f9;
            color: #1e293b;
            font-weight: 600;
        }
        .kv-table tr:hover {
            background-color: #f8fafc;
        }
        .kv-table tbody tr:nth-child(even) {
            background-color: transparent;
        }
        .fallback-text {
            font-size: 13px;
            color: #64748b;
            font-style: italic;
            margin: 10px 0 0 0;
        }
        .meta-summary-bar {
            font-size: 11px;
            text-transform: uppercase;
            color: #64748b;
            font-weight: bold;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 8px 12px;
            border-radius: 8px;
        }

        /* Colorful stat tiles — matches the app's own summary tile grids
           (e.g. Email Harvesting's Total/Employee/Role/Leaked cards) */
        .stat-tile-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        .stat-tile {
            border-radius: 14px;
            padding: 14px;
            text-align: center;
            border: 1px solid;
        }
        .stat-tile .st-label {
            font-size: 9px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }
        .stat-tile .st-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 800;
        }
        .stat-tile .st-sub {
            font-size: 9px;
            font-weight: 600;
            margin-top: 3px;
            opacity: .85;
        }
        .stat-violet { background: #f5f3ff; border-color: #ddd6fe; } .stat-violet .st-label { color: #7c3aed; } .stat-violet .st-value { color: #6d28d9; } .stat-violet .st-sub { color: #8b5cf6; }
        .stat-blue   { background: #eff6ff; border-color: #bfdbfe; } .stat-blue .st-label { color: #2563eb; } .stat-blue .st-value { color: #1d4ed8; } .stat-blue .st-sub { color: #3b82f6; }
        .stat-teal   { background: #f0fdfa; border-color: #99f6e4; } .stat-teal .st-label { color: #0d9488; } .stat-teal .st-value { color: #0f766e; } .stat-teal .st-sub { color: #14b8a6; }
        .stat-rose   { background: #fff1f2; border-color: #fecdd3; } .stat-rose .st-label { color: #e11d48; } .stat-rose .st-value { color: #be123c; } .stat-rose .st-sub { color: #f43f5e; }
        .stat-emerald{ background: #ecfdf5; border-color: #a7f3d0; } .stat-emerald .st-label { color: #059669; } .stat-emerald .st-value { color: #047857; } .stat-emerald .st-sub { color: #10b981; }
        .stat-amber  { background: #fffbeb; border-color: #fde68a; } .stat-amber .st-label { color: #b45309; } .stat-amber .st-value { color: #92400e; } .stat-amber .st-sub { color: #d97706; }
        .stat-slate  { background: #f8fafc; border-color: #e2e8f0; } .stat-slate .st-label { color: #475569; } .stat-slate .st-value { color: #1e293b; } .stat-slate .st-sub { color: #64748b; }
        .stat-red    { background: #fef2f2; border-color: #fecaca; } .stat-red .st-label { color: #dc2626; } .stat-red .st-value { color: #b91c1c; } .stat-red .st-sub { color: #ef4444; }

        /* Pill filter tabs (Email Harvesting "Show All / Employee / Role / Leaked") */
        .pill-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 8px;
            margin-bottom: 16px;
        }
        .pill-tab {
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 6px 12px;
            border-radius: 8px;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            color: #475569;
        }
        .pill-tab.active {
            background: #4f46e5;
            border-color: #4f46e5;
            color: #ffffff;
        }

        /* Row-list — a softer alternative to bordered <table> for dense
           lists (matches the app's own divide-y row lists) */
        .row-list {
            border: 1px solid #e2e8f0;
            border-radius: 14px;
            overflow: hidden;
        }
        .row-list-header {
            display: grid;
            background: #f1f5f9;
            padding: 10px 16px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #64748b;
            border-bottom: 1px solid #e2e8f0;
        }
        .row-list-row {
            display: grid;
            align-items: center;
            padding: 11px 16px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 12px;
        }
        .row-list-row:last-child { border-bottom: none; }
        .row-list-row:hover { background: #f8fafc; }
        .badge-pill {
            display: inline-block;
            font-size: 9px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 3px 9px;
            border-radius: 999px;
        }
        .source-chip {
            display: inline-block;
            font-size: 10px;
            font-weight: 700;
            padding: 3px 9px;
            border-radius: 8px;
            border: 1px solid;
            margin: 2px;
        }

        /* Sidebar per-module accent colors — mirrors the app's own
           per-nav-item color coding rather than a single flat teal */
        .sidebar-btn.active[data-color="teal"]    { background: #f0fdfa; border-color: #99f6e4; color: #0f766e; }
        .sidebar-btn.active[data-color="blue"]    { background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }
        .sidebar-btn.active[data-color="slate"]   { background: #f1f5f9; border-color: #e2e8f0; color: #334155; }
        .sidebar-btn.active[data-color="amber"]   { background: #fffbeb; border-color: #fde68a; color: #92400e; }
        .sidebar-btn.active[data-color="cyan"]    { background: #ecfeff; border-color: #a5f3fc; color: #0e7490; }
        .sidebar-btn.active[data-color="indigo"]  { background: #eef2ff; border-color: #c7d2fe; color: #4338ca; }
        .sidebar-btn.active[data-color="red"]     { background: #fef2f2; border-color: #fecaca; color: #b91c1c; }
        .sidebar-btn.active[data-color="emerald"] { background: #ecfdf5; border-color: #a7f3d0; color: #047857; }
        .sidebar-btn.active[data-color="violet"]  { background: #f5f3ff; border-color: #ddd6fe; color: #6d28d9; }
        .sidebar-btn.active[data-color="orange"]  { background: #fff7ed; border-color: #fed7aa; color: #c2410c; }
        .sidebar-btn.active[data-color="rose"]    { background: #fff1f2; border-color: #fecdd3; color: #be123c; }
        .sidebar-btn.active[data-color="purple"]  { background: #faf5ff; border-color: #e9d5ff; color: #7e22ce; }
        .sidebar-btn.active[data-color="sky"]     { background: #f0f9ff; border-color: #bae6fd; color: #0369a1; }
        .sidebar-btn.active[data-color="fuchsia"] { background: #fdf4ff; border-color: #f5d0fe; color: #a21caf; }

        @media (max-width: 768px) {
            .grid-2 { grid-template-columns: 1fr; }
        }
        @media print {
            body { background-color: #ffffff; padding: 0; }
            .card { box-shadow: none; page-break-inside: avoid; }
        }

        /* Batch report additions: collapsible per-subdomain sections */
        .subdomain-block {
            background: #fff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .subdomain-block summary {
            cursor: pointer;
            padding: 18px 24px;
            display: flex;
            align-items: center;
            gap: 14px;
            flex-wrap: wrap;
            font-weight: 700;
            list-style: none;
            background: #f8fafc;
        }
        .subdomain-block summary::-webkit-details-marker { display: none; }
        .subdomain-block[open] summary { border-bottom: 1px solid #e2e8f0; }
        .subdomain-name {
            font-family: monospace;
            font-size: 16px;
            color: #0f172a;
        }
        .ip-list {
            font-family: monospace;
            font-size: 12px;
            color: #64748b;
            font-weight: 500;
        }
        .subdomain-content {
            padding: 24px;
        }
        .error-box {
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #991b1b;
            padding: 12px 16px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 12px;
        }

        /* Two-pane report layout (Standard / Deep scan downloads) */
        .report-two-pane {
            display: flex;
            gap: 24px;
            align-items: flex-start;
        }
        .report-sidebar {
            flex: 0 0 240px;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 12px;
            position: sticky;
            top: 20px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03), 0 10px 30px rgba(15, 23, 42, 0.04);
        }
        .report-sidebar-title {
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #94a3b8;
            padding: 8px 12px 12px;
        }
        .sidebar-btn {
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
            text-align: left;
            background: transparent;
            border: 1px solid transparent;
            border-radius: 10px;
            padding: 10px 12px;
            margin-bottom: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #475569;
            cursor: pointer;
            font-family: inherit;
        }
        .sidebar-btn:hover {
            background: #f8fafc;
        }
        .sidebar-btn.active {
            background: #f0fdfa;
            border-color: #99f6e4;
            color: #0f766e;
        }
        .sidebar-btn .nav-badge {
            margin-left: auto;
            background: #e2e8f0;
            color: #475569;
            font-size: 9px;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 6px;
        }
        .sidebar-btn.active .nav-badge {
            background: #ccfbf1;
            color: #0f766e;
        }
        .report-content {
            flex: 1;
            min-width: 0;
        }
        .content-pane .card {
            margin-bottom: 0;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }
        .stat-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 16px;
        }
        .stat-box .label {
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #64748b;
        }
        .stat-box .value {
            font-size: 15px;
            font-weight: 800;
            color: #0f172a;
            margin-top: 6px;
            font-family: monospace;
            word-break: break-all;
        }
        .findings-title {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #64748b;
            margin: 4px 0 12px;
        }
        .findings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        .finding-card {
            display: block;
            width: 100%;
            text-align: left;
            border-radius: 12px;
            padding: 14px;
            border: 1px solid;
            cursor: pointer;
            font-family: inherit;
        }
        .finding-card .f-label {
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: .75;
        }
        .finding-card .f-value {
            font-size: 13px;
            font-weight: 800;
            margin-top: 6px;
        }
        .finding-good { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
        .finding-warning { background: #fffbeb; border-color: #fde68a; color: #92400e; }
        .finding-danger { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
        .finding-neutral { background: #f8fafc; border-color: #e2e8f0; color: #334155; }
        @media (max-width: 768px) {
            .report-two-pane { flex-direction: column; }
            .report-sidebar { position: static; width: 100%; flex-basis: auto; }
        }
`

export function isModuleOk(mod) {
  if (!mod) return false
  if (mod.status === 'error' || mod.error_code) return false
  if (mod.status === 'skipped' && !Object.keys(mod).some(k => k !== 'status' && k !== 'error_code' && k !== 'error_message')) return false
  return true
}

export function moduleStatusBadge(mod) {
  if (!mod) return '<span class="status-badge skipped">NOT RUN</span>'
  if (mod.status === 'error' || mod.error_code) return `<span class="status-badge error">FAILED (${mod.error_code || 'error'})</span>`
  if (mod.status === 'skipped') return `<span class="status-badge skipped">SKIPPED (${mod.reason || 'skipped'})</span>`
  if (mod.status === 'partial') return '<span class="status-badge partial">PARTIAL</span>'
  return '<span class="status-badge ok">OK</span>'
}

// Mirrors EmailGatherSection's SOURCE_COLORS/SOURCE_LABELS in Results.jsx —
// kept in sync by hand since a static HTML export can't import the
// component directly.
const _EMAIL_SOURCE_COLORS = {
  crt_sh: '#3b82f6', pgp_keyserver: '#8b5cf6', ubuntu_pgp: '#a855f7', mit_pgp: '#6366f1',
  wayback_machine: '#f59e0b', wayback_docs: '#d97706', web_crawl: '#10b981', dns_txt_dmarc: '#06b6d4',
  subdomain_dns: '#0284c7', github_search: '#1d4ed8', bing_search: '#eab308', commoncrawl: '#7c3aed',
  alienvault_otx: '#ec4899', threatminer: '#ef4444', urlscan: '#f97316', certspotter: '#14b8a6',
  keybase: '#3b82f6', email_format: '#0284c7', skymem: '#6366f1', smtp_banner: '#64748b',
  ahmia_darkweb: '#dc2626', paste_dumps: '#ea580c', leakix: '#b91c1c', forum_registrations: '#4f46e5',
  gitlab_search: '#fc6d26', duckduckgo_search: '#de5833', qwant_search: '#0055ff',
  bitbucket_gitee: '#2563eb', cloud_storage_buckets: '#0284c7', database_backups: '#b91c1c',
}
const _EMAIL_SOURCE_LABELS = {
  crt_sh: 'crt.sh', pgp_keyserver: 'OpenPGP', ubuntu_pgp: 'Ubuntu PGP', mit_pgp: 'MIT PGP',
  wayback_machine: 'Wayback', wayback_docs: 'Wayback Docs', web_crawl: 'Web Crawl', dns_txt_dmarc: 'DNS/DMARC',
  subdomain_dns: 'Subdomain DNS', github_search: 'GitHub', bing_search: 'Bing', commoncrawl: 'CommonCrawl',
  alienvault_otx: 'AlienVault OTX', threatminer: 'ThreatMiner', urlscan: 'URLScan', certspotter: 'CertSpotter',
  keybase: 'Keybase', email_format: 'Email-Format', skymem: 'Skymem', smtp_banner: 'SMTP Banner',
  ahmia_darkweb: 'Ahmia Darkweb', paste_dumps: 'Paste Dumps', leakix: 'LeakIX', forum_registrations: 'Forums & Events',
  gitlab_search: 'GitLab', duckduckgo_search: 'DuckDuckGo', qwant_search: 'Qwant',
  bitbucket_gitee: 'Bitbucket/Gitee', cloud_storage_buckets: 'Cloud Buckets', database_backups: 'DB Backups',
}

function _portsCard(ports) {
  if (!isModuleOk(ports)) return '<p class="fallback-text">No port scanning information was successfully collected.</p>'
  const openPorts = ports.open_ports || []
  const stats = `
    <div class="stat-tile-grid">
        <div class="stat-tile stat-slate"><div class="st-label">Scanned</div><div class="st-value">${ports.scanned_port_count || 0}</div></div>
        <div class="stat-tile stat-emerald"><div class="st-label">Open</div><div class="st-value">${ports.open_port_count || 0}</div></div>
        <div class="stat-tile stat-slate"><div class="st-label">Closed</div><div class="st-value">${ports.closed_port_count || 0}</div></div>
        <div class="stat-tile stat-amber"><div class="st-label">Filtered</div><div class="st-value">${ports.filtered_port_count || 0}</div></div>
    </div>
  `
  if (openPorts.length === 0) {
    return stats + '<p class="fallback-text">No active listening services detected on the scanned ports.</p>'
  }
  return stats + `
    <div class="row-list">
        <div class="row-list-header" style="grid-template-columns: 1fr 2fr 1.5fr 2.5fr;">
            <div>Port</div><div>Service</div><div>Version</div><div>Banner</div>
        </div>
        ${openPorts.map(p => `
        <div class="row-list-row" style="grid-template-columns: 1fr 2fr 1.5fr 2.5fr;">
            <div class="mono" style="font-weight: 700; color: #4338ca;">${p.port}</div>
            <div style="font-weight: 600;">${p.service || 'unknown'}</div>
            <div>${p.version ? `<span class="tag tag-teal">${p.version}</span>` : '<span style="color:#94a3b8;">—</span>'}</div>
            <div class="mono" style="font-size: 11px; color: #64748b; word-break: break-all;">${p.banner || '—'}</div>
        </div>
        `).join('')}
    </div>
  `
}

function _directoryEnumCard(dirEnum) {
  if (!isModuleOk(dirEnum)) return '<p class="fallback-text">Directory enumeration was not executed.</p>'
  const found = dirEnum.found || []
  const stats = `
    <div class="stat-tile-grid">
        <div class="stat-tile stat-slate"><div class="st-label">Paths Checked</div><div class="st-value">${dirEnum.paths_checked || 0}</div></div>
        <div class="stat-tile stat-emerald"><div class="st-label">Found</div><div class="st-value">${found.length}</div></div>
    </div>
  `
  if (found.length === 0) return stats + '<p class="fallback-text">No open directories/files were found.</p>'
  const statusColor = (s) => s === 200 ? '#16a34a' : s === 403 ? '#dc2626' : (s >= 300 && s < 400) ? '#2563eb' : '#64748b'
  return stats + `
    <div class="row-list">
        <div class="row-list-header" style="grid-template-columns: 0.7fr 3fr 1.3fr;">
            <div>Status</div><div>Path & URL</div><div>Content Type</div>
        </div>
        ${found.map(p => `
        <div class="row-list-row" style="grid-template-columns: 0.7fr 3fr 1.3fr;">
            <div><span class="badge-pill" style="background: ${statusColor(p.status)}1a; color: ${statusColor(p.status)};">${p.status}</span></div>
            <div class="mono" style="font-weight: 700; color: #0f172a; word-break: break-all;">
                ${p.path}
                ${p.url ? `<br><a href="${p.url}" target="_blank" style="font-size: 10px; color: #0284c7; font-weight: 500; text-decoration: none;">${p.url}</a>` : ''}
            </div>
            <div style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600;">${p.content_type || '—'}</div>
        </div>
        `).join('')}
    </div>
  `
}

function _subdomainsCard(subdomains, isDomain) {
  if (!isDomain) return '<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>'
  if (!isModuleOk(subdomains)) return '<p class="fallback-text">No subdomain enumeration was executed.</p>'
  const list = subdomains.subdomains || []
  const rawCount = Object.values(subdomains.sources || {}).reduce((acc, curr) => acc + (curr.count || 0), 0)
  const stats = `
    <div class="stat-tile-grid">
        <div class="stat-tile stat-violet"><div class="st-label">Unique Subdomains</div><div class="st-value">${list.length}</div></div>
        <div class="stat-tile stat-slate"><div class="st-label">Raw Matches</div><div class="st-value">${rawCount}</div><div class="st-sub">before dedup</div></div>
    </div>
  `
  if (list.length === 0) return stats + '<p class="fallback-text">No subdomains were discovered.</p>'
  return stats + `
    <div class="row-list">
        <div class="row-list-header" style="grid-template-columns: 2.5fr 1.5fr 1.5fr;">
            <div>Subdomain</div><div>Resolved IP</div><div>Source</div>
        </div>
        ${list.map(s => `
        <div class="row-list-row" style="grid-template-columns: 2.5fr 1.5fr 1.5fr;">
            <div class="mono" style="font-weight: 700; color: #6d28d9; word-break: break-all;">${s.subdomain}</div>
            <div class="mono">${s.ip ? `<span style="color:#15803d; font-weight:700;">${s.ip}</span>` : '<span style="color:#94a3b8;">—</span>'}</div>
            <div><span class="badge-pill" style="background:#f5f3ff; color:#6d28d9;">${s.source || '—'}</span></div>
        </div>
        `).join('')}
    </div>
  `
}

function _emailHarvestingCard(emailData, isDomain) {
  if (!isDomain) return '<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>'
  if (!isModuleOk(emailData)) return '<p class="fallback-text">Email harvesting was not executed.</p>'

  const emails = emailData.emails || []
  const employeeCount = emailData.employee_accounts_count ?? emails.filter(e => e.account_type === 'employee').length
  const roleCount = emailData.role_accounts_count ?? emails.filter(e => e.account_type === 'role').length
  const leakedCount = emailData.leaked_accounts_count ?? emails.filter(e => e.is_leaked).length
  const totalFound = emailData.total_found ?? emails.length

  if (emails.length === 0) {
    return `
    <div class="stat-tile-grid">
        <div class="stat-tile stat-violet"><div class="st-label">Total Found</div><div class="st-value">${totalFound}</div><div class="st-sub">unique emails</div></div>
        <div class="stat-tile stat-blue"><div class="st-label">Employee Accounts</div><div class="st-value">${employeeCount}</div><div class="st-sub">individual staff</div></div>
        <div class="stat-tile stat-teal"><div class="st-label">Role Accounts</div><div class="st-value">${roleCount}</div><div class="st-sub">group / admin</div></div>
        <div class="stat-tile stat-rose"><div class="st-label">Leaked / Exposed</div><div class="st-value">${leakedCount}</div><div class="st-sub">public leak exposure</div></div>
    </div>
    <p class="fallback-text">No email addresses discovered for this domain.</p>
    `
  }

  return `
    <div class="stat-tile-grid">
        <div class="stat-tile stat-violet"><div class="st-label">Total Found</div><div class="st-value">${totalFound}</div><div class="st-sub">unique emails</div></div>
        <div class="stat-tile stat-blue"><div class="st-label">Employee Accounts</div><div class="st-value">${employeeCount}</div><div class="st-sub">individual staff</div></div>
        <div class="stat-tile stat-teal"><div class="st-label">Role Accounts</div><div class="st-value">${roleCount}</div><div class="st-sub">group / admin</div></div>
        <div class="stat-tile stat-rose"><div class="st-label">Leaked / Exposed</div><div class="st-value">${leakedCount}</div><div class="st-sub">public leak exposure</div></div>
    </div>
    <div class="row-list">
        <div class="row-list-header" style="grid-template-columns: 2fr 1fr 2fr;">
            <div>Email Address</div>
            <div style="text-align:center;">Type</div>
            <div style="text-align:right;">Sources</div>
        </div>
        ${emails.map(e => `
        <div class="row-list-row" style="grid-template-columns: 2fr 1fr 2fr;">
            <div class="mono" style="font-weight: 700; color: #0f172a; word-break: break-all;">${e.email}</div>
            <div style="text-align:center;">
                <span class="badge-pill" style="background: ${e.account_type === 'employee' ? '#dbeafe' : '#e2e8f0'}; color: ${e.account_type === 'employee' ? '#1e40af' : '#334155'};">${e.account_type === 'employee' ? 'Employee' : 'Role'}</span>
                ${e.is_leaked ? `<span class="badge-pill" style="background:#ffe4e6; color:#be123c; margin-left:4px;">Leaked</span>` : ''}
            </div>
            <div style="text-align:right;">
                ${(e.sources || []).map(src => {
                  const c = _EMAIL_SOURCE_COLORS[src] || '#64748b'
                  return `<span class="source-chip" style="background: ${c}1a; color: ${c}; border-color: ${c}33;">${_EMAIL_SOURCE_LABELS[src] || src}</span>`
                }).join('')}
            </div>
        </div>
        `).join('')}
    </div>
  `
}

export function buildScanReportBody(data) {
  const r = data.results || {}
  const geo = r.geo_ip || {}
  const ports = r.port_scan || {}
  const dns = r.dns_records || {}
  const ssl = r.ssl_certificate || {}
  const tech = r.web_technologies || {}
  const headers = r.http_headers || {}
  const subdomains = r.subdomains || {}
  // run_scan()'s task dict keys this "directories" (main.py), not
  // "directory_enum" — Results.jsx checks both (directory_enum kept only
  // as a legacy fallback). This export was checking directory_enum only,
  // which made real directory-enum results silently report as "not
  // executed" even when they'd actually run and found data.
  const dirEnum = r.directories || r.directory_enum

  const isOk = isModuleOk
  const getStatusLabel = moduleStatusBadge

  return `
        <!-- Target Panel -->
        <div class="target-panel">
            <div class="target-panel-label">Diagnostics Panel</div>
            <h1 class="target-panel-name">${data.target}</h1>
            <div class="target-panel-meta">
                ${data.resolved_ip && data.resolved_ip !== data.target ? `<span>Resolved IP: ${data.resolved_ip}</span><span class="sep">|</span>` : ''}
                <span>Duration: ${data.scan_duration_seconds ? data.scan_duration_seconds + 's' : 'N/A'}</span>
                <span class="sep">|</span>
                <span class="mode-tag">${(data.scan_mode || 'fast').toUpperCase()}</span>
            </div>
        </div>

        <!-- Cloud Provider Detection -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">☁️ Cloud Provider</h3>
                ${getStatusLabel(r.cloud_provider)}
            </div>
            ${isOk(r.cloud_provider) ? `
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                <div style="background-color: ${r.cloud_provider.cloud_detected ? '#eff6ff' : '#f8fafc'}; color: ${r.cloud_provider.cloud_detected ? '#1d4ed8' : '#475569'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.cloud_provider.cloud_detected ? '#bfdbfe' : '#e2e8f0'};">
                    ${r.cloud_provider.cloud_detected ? r.cloud_provider.provider : 'Self-Hosted / Non-Cloud'}
                </div>
                ${r.cloud_provider.confidence ? `<span class="tag">${r.cloud_provider.confidence} confidence</span>` : ''}
            </div>
            <table class="kv-table" style="font-size: 12px;">
                <tr><th style="width: 40%;">Detection Method</th><td><span class="mono">${r.cloud_provider.method || '—'}</span></td></tr>
                ${r.cloud_provider.ranges_checked !== undefined ? `<tr><th>CIDR Ranges Checked</th><td>${r.cloud_provider.ranges_checked.toLocaleString()}</td></tr>` : ''}
                ${r.cloud_provider.asn_org ? `<tr><th>ASN Organization</th><td>${r.cloud_provider.asn_org}</td></tr>` : ''}
                ${r.cloud_provider.asn_isp ? `<tr><th>ISP Provider</th><td>${r.cloud_provider.asn_isp}</td></tr>` : ''}
                ${r.cloud_provider.as_number ? `<tr><th>AS Number</th><td>${r.cloud_provider.as_number}</td></tr>` : ''}
                ${r.cloud_provider.is_hosting !== undefined ? `<tr><th>Server Hosting</th><td>${r.cloud_provider.is_hosting ? 'Yes (Datacenter)' : 'No (Residential/Business)'}</td></tr>` : ''}
            </table>
            ` : `<p class="fallback-text">Cloud provider detection not available.</p>`}
        </div>

        <!-- Geolocation Overview -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📍 Geolocation & Host Info</h3>
                ${getStatusLabel(r.geo_ip)}
            </div>
            ${isOk(r.geo_ip) ? `
            <table class="kv-table">
                <tr><th style="width: 30%;">IP Address</th><td>${geo.ip || 'N/A'}</td></tr>
                <tr><th>Country</th><td>${geo.country ? `${geo.country} (${geo.country_code || 'N/A'})` : 'N/A'}</td></tr>
                <tr><th>Region / State</th><td>${geo.region || 'N/A'}</td></tr>
                <tr><th>City</th><td>${geo.city || 'N/A'}</td></tr>
                <tr><th>Coordinates</th><td>${geo.latitude && geo.longitude ? `${geo.latitude}, ${geo.longitude}` : 'N/A'}</td></tr>
                <tr><th>Timezone</th><td>${geo.timezone || 'N/A'}</td></tr>
                <tr><th>ISP Provider</th><td>${geo.isp || 'N/A'}</td></tr>
                <tr><th>Organization</th><td>${geo.organization || geo.org || 'N/A'}</td></tr>
                <tr><th>ASN Number</th><td>${geo.asn || 'N/A'}</td></tr>
                <tr><th>Hosting Server</th><td>${geo.is_hosting ? 'Yes (Cloud/Server)' : 'No'}</td></tr>
                <tr><th>Proxy / VPN Network</th><td>${geo.is_proxy ? 'Yes' : 'No'}</td></tr>
            </table>
            ` : `<p class="fallback-text">No geolocation details available for this host.</p>`}
        </div>

        <!-- Active Services & Ports -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🖥️ Active Services & Ports</h3>
                ${getStatusLabel(r.port_scan)}
            </div>
            ${_portsCard(ports)}
        </div>

        <!-- Reverse DNS PTR Record -->
        ${r.reverse_dns && r.reverse_dns.status !== 'skipped' ? `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🌐 Reverse DNS Pointer</h3>
                ${getStatusLabel(r.reverse_dns)}
            </div>
            ${r.reverse_dns.hostname ? `
            <div class="mono" style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px;">
                <div style="font-weight: bold; color: #0f172a;">${r.reverse_dns.hostname}</div>
                ${r.reverse_dns.nslookup_resolver_hostname && r.reverse_dns.nslookup_resolver_hostname !== r.reverse_dns.hostname ? `
                <div style="font-size: 10px; color: #64748b; margin-top: 4px;">
                    Comparing resolvers: Socket resolution resolved <strong>${r.reverse_dns.primary_resolver_hostname || '—'}</strong>, nslookup resolved <strong>${r.reverse_dns.nslookup_resolver_hostname}</strong>
                </div>
                ` : ''}
            </div>
            ` : `<p class="fallback-text">No PTR record found.</p>`}
        </div>
        ` : ''}

        <!-- Domain & DNS Records -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🌐 DNS Records</h3>
                ${data.is_domain ? getStatusLabel(r.dns_records) : '<span class="status-badge skipped">SKIPPED</span>'}
            </div>
            ${data.is_domain ? (
              isOk(r.dns_records) && dns.records_by_type ? `
              <div class="dns-grid">
                  ${["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"].map(type => {
                    const result = dns.records_by_type[type]
                    if (!result) return ''
                    const recs = result.records || []
                    return `
                                  <div class="dns-record-block" style="margin-bottom: 15px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                                      <div style="font-family: monospace; font-size: 11px; font-weight: bold; color: #ea580c; margin-bottom: 6px;">${type}</div>
                                      ${recs.length === 0 ? `
                                      <div class="mono" style="font-size: 11px; color: #94a3b8; font-style: italic;">No ${type} records configured.</div>
                                      ` : `
                                      ${typeof recs[0] !== 'object' ? `
                                      <table style="border: 1px solid #e2e8f0; border-radius: 4px; font-size: 11px; width: 100%; border-collapse: collapse;">
                                          <thead><tr style="background-color: #f1f5f9;"><th style="width: 20%; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Type</th><th style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Record / Address</th></tr></thead>
                                          <tbody>
                                              ${recs.map(rec => `<tr><td style="font-weight: bold; color: #0284c7; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${type}</td><td class="mono" style="word-break: break-all; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${rec}</td></tr>`).join('')}
                                          </tbody>
                                      </table>
                                      ` : `
                                      <table style="border: 1px solid #e2e8f0; border-radius: 4px; font-size: 11px; width: 100%; border-collapse: collapse;">
                                          <thead><tr style="background-color: #f1f5f9;"><th style="width: 20%; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Type</th>${Object.keys(recs[0]).map(k => `<th style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left; text-transform: uppercase;">${k.replace(/_/g, ' ')}</th>`).join('')}</tr></thead>
                                          <tbody>
                                              ${recs.map(rec => `<tr><td style="font-weight: bold; color: #0284c7; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${type}</td>${Object.keys(recs[0]).map(k => `<td class="mono" style="word-break: break-all; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${String(rec[k])}</td>`).join('')}</tr>`).join('')}
                                          </tbody>
                                      </table>
                                      `}
                                      `}
                                  </div>
                                  `
                  }).join('')}
              </div>
              ` : `<p class="fallback-text">No DNS records resolved.</p>`
            ) : `<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>`}
        </div>

        <!-- WHOIS Registration -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📄 Domain Registration (WHOIS)</h3>
                ${data.is_domain ? getStatusLabel(r.whois) : '<span class="status-badge skipped">SKIPPED</span>'}
            </div>
            ${data.is_domain ? (
              isOk(r.whois) ? `
              <table class="kv-table">
                  <tr><th style="width: 30%;">Registrar Host</th><td>${r.whois.registrar || '—'}</td></tr>
                  <tr><th>Registrar IANA ID</th><td>${r.whois.registrar_iana_id || '—'}</td></tr>
                  <tr><th>Registrar Abuse Email</th><td>${r.whois.registrar_abuse_email || '—'}</td></tr>
                  <tr><th>Registrar Abuse Phone</th><td>${r.whois.registrar_abuse_phone || '—'}</td></tr>
                  <tr><th>Registered Date</th><td>${r.whois.creation_date ? new Date(r.whois.creation_date).toLocaleDateString() : '—'}</td></tr>
                  <tr><th>Expiration Date</th><td>${r.whois.expiration_date ? new Date(r.whois.expiration_date).toLocaleDateString() : '—'}</td></tr>
                  <tr><th>Last Modified Date</th><td>${r.whois.updated_date ? new Date(r.whois.updated_date).toLocaleDateString() : '—'}</td></tr>
                  <tr><th>Days Until Expiry</th><td>${r.whois.days_until_expiry != null ? `${r.whois.days_until_expiry} days` : '—'}</td></tr>
                  <tr><th>Expiry Status</th><td>${r.whois.expiry_status || '—'}</td></tr>
                  <tr><th>Registrant Name</th><td>${r.whois.registrant_name || '—'}</td></tr>
                  <tr><th>Registrant Org</th><td>${r.whois.registrant_org || r.whois.org || '—'}</td></tr>
                  <tr><th>Registrant Country</th><td>${r.whois.country || '—'}</td></tr>
                  <tr><th>Registrant State</th><td>${r.whois.state || '—'}</td></tr>
                  <tr><th>Registrant City</th><td>${r.whois.city || '—'}</td></tr>
                  <tr><th>DNSSEC Status</th><td>${r.whois.dnssec || '—'}</td></tr>
                  <tr><th>Name Servers</th><td>
                      ${r.whois.name_servers && r.whois.name_servers.length > 0 ?
                      `<div style="display: flex; flex-direction: column; gap: 4px;">
                          ${r.whois.name_servers.map(ns => `<span class="mono" style="font-size: 11px;">${ns}</span>`).join('')}
                      </div>` : '—'}
                  </td></tr>
              </table>
              ` : `<p class="fallback-text">WHOIS details not available.</p>`
            ) : `<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>`}
        </div>

        <!-- SSL/TLS Security Certificate -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🔒 SSL/TLS Security Certificate</h3>
                ${data.is_domain ? getStatusLabel(r.ssl_certificate) : '<span class="status-badge skipped">SKIPPED</span>'}
            </div>
            ${data.is_domain ? (
              isOk(r.ssl_certificate) ? `
              ${ssl.days_until_expiry !== null && ssl.days_until_expiry !== undefined ? `
              <div style="font-size: 11px; font-weight: bold; margin-bottom: 15px; padding: 8px; border: 1px solid ${ssl.days_until_expiry < 0 ? '#fecaca' : '#bbf7d0'}; border-radius: 6px; background-color: ${ssl.days_until_expiry < 0 ? '#fef2f2' : '#f0fdf4'}; color: ${ssl.days_until_expiry < 0 ? '#b91c1c' : '#15803d'}; display: inline-block;">
                  Status: ${ssl.days_until_expiry < 0 ? `Expired ${-ssl.days_until_expiry} days ago` : `Expires in ${ssl.days_until_expiry} days`}
              </div>
              ` : ''}
              <table class="kv-table" style="margin-bottom: 20px;">
                  <tr><th style="width: 30%;">Common Name (CN)</th><td><strong>${ssl.subject_common_name || 'N/A'}</strong></td></tr>
                  <tr><th>Certificate Issuer</th><td>${ssl.issuer_common_name || 'N/A'}</td></tr>
                  <tr><th>Issuer Org</th><td>${ssl.issuer_organization || 'N/A'}</td></tr>
                  <tr><th>Valid From</th><td>${ssl.valid_from || 'N/A'}</td></tr>
                  <tr><th>Valid Until</th><td>${ssl.valid_until || 'N/A'}</td></tr>
                  <tr><th>Negotiated Protocol</th><td class="mono">${ssl.protocol || 'N/A'}</td></tr>
                  <tr><th>Negotiated Cipher</th><td class="mono">${ssl.cipher_suite || 'N/A'}</td></tr>
              </table>

              ${ssl.supported_protocols && Object.keys(ssl.supported_protocols).length > 0 ? `
              <div style="margin-top: 15px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
                  <h4 style="font-size: 10px; text-transform: uppercase; color: #115e59; margin-bottom: 10px;">Supported TLS Protocols & Cipher Suites</h4>
                  <table style="width: 100%; border-collapse: collapse; font-size: 11px; border: 1px solid #ccfbf1; border-radius: 8px;">
                      <thead>
                          <tr style="background-color: #f0fdfa;">
                              <th style="padding: 8px; border-bottom: 1px solid #ccfbf1; text-align: left; width: 25%;">Protocol</th>
                              <th style="padding: 8px; border-bottom: 1px solid #ccfbf1; text-align: left; width: 75%;">Supported Cipher Suites</th>
                          </tr>
                      </thead>
                      <tbody>
                          ${Object.entries(ssl.supported_protocols).map(([proto, ciphers]) => `
                          <tr>
                              <td style="padding: 8px; border-bottom: 1px solid #f0fdfa; vertical-align: top;">
                                  <span style="background-color: #0d9488; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;">${proto}</span>
                                  <div style="font-size: 9px; color: #64748b; margin-top: 6px;">${ciphers.length} cipher(s)</div>
                              </td>
                              <td style="padding: 8px; border-bottom: 1px solid #f0fdfa; font-family: monospace;">
                                  <div style="display: flex; flex-direction: column; gap: 4px;">
                                      ${ciphers.map(cipher => `
                                      <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 4px 8px; border-radius: 4px; word-break: break-all;">${cipher}</div>
                                      `).join('')}
                                  </div>
                              </td>
                          </tr>
                          `).join('')}
                      </tbody>
                  </table>
              </div>
              ` : ''}

              ${ssl.subject_alternative_names && ssl.subject_alternative_names.length > 0 ? `
              <div style="margin-top: 15px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
                  <h4 style="font-size: 10px; text-transform: uppercase; color: #115e59; margin-bottom: 10px;">Alternative Subject Names (SANs)</h4>
                  <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                      ${ssl.subject_alternative_names.map(san => `
                      <span style="font-size: 10px; background-color: white; border: 1px solid #ccfbf1; padding: 4px 8px; border-radius: 4px; color: #115e59; font-weight: bold; font-family: monospace;">${san}</span>
                      `).join('')}
                  </div>
              </div>
              ` : ''}
              ` : `<p class="fallback-text">No SSL certificate details fetched.</p>`
            ) : `<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>`}
        </div>

        <!-- Web Application Stack -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🛠️ Web Application Stack</h3>
                ${getStatusLabel(r.web_technologies)}
            </div>
            ${isOk(r.web_technologies) && tech.technologies ? `
            ${tech.weak_tls_downgrade ? `<p class="fallback-text" style="color: #92400e;">${tech.weak_tls_note || ''}</p>` : ''}
            <table class="kv-table" style="margin-bottom: 15px;">
                <tr><th style="width: 30%;">Server Header</th><td class="mono">${tech.meta?.server || '—'}</td></tr>
                <tr><th>Powered By</th><td class="mono">${tech.meta?.powered_by || '—'}</td></tr>
                <tr><th>Content Type</th><td class="mono">${tech.meta?.content_type || '—'}</td></tr>
            </table>
            <div>
                <h4 style="font-size: 12px; text-transform: uppercase; color: #0f172a; margin-bottom: 8px;">Detected Component Stack</h4>
                ${Object.entries(tech.technologies).length > 0 ? `
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    ${Object.entries(tech.technologies).map(([cat, list]) => `
                    <div>
                        <div style="font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: bold; margin-bottom: 4px;">${cat.replace('_', ' ')}</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                            ${list.map(t => `<span class="tag tag-teal" style="font-weight: bold;">${t}</span>`).join('')}
                        </div>
                    </div>
                    `).join('')}
                </div>
                ` : '<p style="font-size: 11px; font-style: italic; color: #64748b;">No signature-matched web framework signatures detected.</p>'}
            </div>
            ` : `<p class="fallback-text">No web application stack scan was collected.</p>`}
        </div>

        <!-- CMS Fingerprint -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🧩 CMS Fingerprint</h3>
                ${getStatusLabel(r.cms_fingerprint)}
            </div>
            ${isOk(r.cms_fingerprint) ? `
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                <div style="background-color: ${r.cms_fingerprint.cms_detected ? '#fdf4ff' : '#f8fafc'}; color: ${r.cms_fingerprint.cms_detected ? '#a21caf' : '#475569'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.cms_fingerprint.cms_detected ? '#f5d0fe' : '#e2e8f0'};">
                    ${r.cms_fingerprint.cms_detected ? r.cms_fingerprint.cms_name : 'Custom / Non-CMS Site'}
                    ${r.cms_fingerprint.version ? `<span style="margin-left: 8px; font-size: 12px; color: #d946ef; font-family: monospace;">v${r.cms_fingerprint.version}</span>` : ''}
                </div>
            </div>
            ` : `<p class="fallback-text">CMS fingerprinting not available.</p>`}
        </div>

        <!-- WAF Detection -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🛡️ Web Application Firewall</h3>
                ${getStatusLabel(r.waf_detect)}
            </div>
            ${isOk(r.waf_detect) ? `
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                <div style="background-color: ${r.waf_detect.waf_detected ? '#fef2f2' : '#f0fdf4'}; color: ${r.waf_detect.waf_detected ? '#b91c1c' : '#15803d'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.waf_detect.waf_detected ? '#fecaca' : '#bbf7d0'};">
                    ${r.waf_detect.waf_detected ? r.waf_detect.waf_name : 'No WAF Detected'}
                </div>
            </div>
            ${r.waf_detect.waf_detected && r.waf_detect.all_detected && r.waf_detect.all_detected.length > 1 ? `
            <p style="font-size: 12px; color: #64748b; margin-bottom: 15px;">Multiple WAF layers detected: ${r.waf_detect.all_detected.join(', ')}.</p>
            ` : ''}
            ${r.waf_detect.probes && r.waf_detect.probes.length > 0 ? `
            <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 8px;">Attack Probes</h4>
            <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                ${r.waf_detect.probes.map(p => `
                <div style="border: 1px solid ${p.likely_blocked ? '#fecaca' : '#e2e8f0'}; background-color: ${p.likely_blocked ? '#fef2f2' : '#f8fafc'}; padding: 10px; border-radius: 8px; min-width: 120px;">
                    <div style="font-size: 9px; text-transform: uppercase; color: #64748b; margin-bottom: 4px;">${p.probe.replace(/_/g, ' ')}</div>
                    <div style="font-size: 18px; font-weight: bold; color: ${p.likely_blocked ? '#b91c1c' : '#0f172a'};">${p.status_code}</div>
                    <div style="font-size: 10px; font-weight: bold; color: ${p.likely_blocked ? '#ef4444' : '#10b981'}; text-transform: uppercase;">${p.likely_blocked ? 'Blocked' : 'Passed'}</div>
                </div>
                `).join('')}
            </div>
            ` : ''}
            ` : `<p class="fallback-text">WAF detection not available.</p>`}
        </div>

        <!-- Security Headers Check -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🛡️ Security Headers Check</h3>
                ${getStatusLabel(r.http_headers)}
            </div>
            ${isOk(r.http_headers) ? `
            <div class="grid-2">
                <div>
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #166534; margin-bottom: 8px;">Present Security Headers</h4>
                    ${headers.security_headers_present && Object.keys(headers.security_headers_present).length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        ${Object.entries(headers.security_headers_present).map(([h, val]) => `
                        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 6px 10px; border-radius: 6px; font-size: 11px;">
                            <strong style="color: #166534;">${h}</strong>
                            <div class="mono" style="margin-top: 4px; font-size: 10px; word-break: break-all;">${val}</div>
                        </div>
                        `).join('')}
                    </div>
                    ` : '<p style="font-size: 11px; font-style: italic; color: #166534;">None of the target security headers were found.</p>'}
                </div>
                <div>
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #991b1b; margin-bottom: 8px;">Missing Security Headers</h4>
                    ${headers.security_headers_missing && headers.security_headers_missing.length > 0 ? `
                    <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                        ${headers.security_headers_missing.map(h => `
                        <span class="tag" style="background-color: #fef2f2; border-color: #fee2e2; color: #991b1b; padding: 4px 8px; font-weight: bold;">
                            ${h}
                        </span>
                        `).join('')}
                    </div>
                    ` : '<p style="font-size: 11px; font-style: italic; color: #166534;">All standard security headers are present!</p>'}
                </div>
            </div>
            ` : `<p class="fallback-text">No security headers analysis was collected.</p>`}
        </div>

        <!-- Subdomains Index -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📁 Subdomains Index</h3>
                ${data.is_domain ? getStatusLabel(r.subdomains) : '<span class="status-badge skipped">SKIPPED</span>'}
            </div>
            ${_subdomainsCard(subdomains, data.is_domain)}
        </div>

        <!-- Directory Enumeration -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📂 Directory Enumeration</h3>
                ${getStatusLabel(dirEnum)}
            </div>
            ${_directoryEnumCard(dirEnum)}
        </div>

        <!-- IP Reputation & Threat Intelligence -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">⚠️ IP Reputation & Threat Intelligence</h3>
                <div>
                    ${getStatusLabel(r.abuseipdb)} ${getStatusLabel(r.virustotal)}
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <!-- AbuseIPDB -->
                ${isOk(r.abuseipdb) ? `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px;">
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; font-weight: bold;">AbuseIPDB Reputation</h4>
                    <table class="kv-table" style="font-size: 12px;">
                        <tr><th style="width: 50%;">IP Address</th><td class="mono" style="font-weight: bold;">${r.abuseipdb.ip || '—'}</td></tr>
                        <tr><th>Threat Level</th><td><span style="font-weight: bold; color: ${r.abuseipdb.threat_level === 'critical' ? '#b91c1c' : r.abuseipdb.threat_level === 'high' ? '#dc2626' : r.abuseipdb.threat_level === 'medium' ? '#f59e0b' : '#10b981'};">${(r.abuseipdb.threat_level || '—').toUpperCase()}</span></td></tr>
                        <tr><th>Abuse Confidence</th><td><strong style="color: ${r.abuseipdb.abuse_confidence_score > 75 ? '#b91c1c' : r.abuseipdb.abuse_confidence_score > 50 ? '#f59e0b' : '#10b981'};">${r.abuseipdb.abuse_confidence_score || 0}%</strong></td></tr>
                        <tr><th>Total Reports</th><td><strong>${r.abuseipdb.total_reports || 0}</strong></td></tr>
                        <tr><th>Country</th><td>${r.abuseipdb.country_name ? `${r.abuseipdb.country_name} (${r.abuseipdb.country_code})` : '—'}</td></tr>
                        <tr><th>ISP/Organization</th><td>${r.abuseipdb.isp || '—'}</td></tr>
                        <tr><th>Tor Network</th><td>${r.abuseipdb.is_tor ? '<span style="color: #b91c1c; font-weight: bold;">YES (Exit Node)</span>' : 'No'}</td></tr>
                        <tr><th>VPN/Proxy</th><td>${r.abuseipdb.is_proxy ? '<span style="color: #f59e0b; font-weight: bold;">YES</span>' : 'No'}</td></tr>
                        <tr><th>Whitelisted</th><td>${r.abuseipdb.is_whitelisted ? '<span style="color: #10b981; font-weight: bold;">YES</span>' : 'No'}</td></tr>
                    </table>
                </div>
                ` : `<p class="fallback-text">AbuseIPDB reputation data not available.</p>`}

                <!-- VirusTotal -->
                ${isOk(r.virustotal) ? `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px;">
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; font-weight: bold;">VirusTotal Scan Results</h4>
                    <table class="kv-table" style="font-size: 12px;">
                        <tr><th style="width: 50%;">Target</th><td class="mono" style="font-weight: bold;">${r.virustotal.target || '—'}</td></tr>
                        <tr><th>Threat Level</th><td><span style="font-weight: bold; color: ${r.virustotal.threat_level === 'critical' ? '#b91c1c' : r.virustotal.threat_level === 'high' ? '#dc2626' : r.virustotal.threat_level === 'medium' ? '#f59e0b' : '#10b981'};">${(r.virustotal.threat_level || '—').toUpperCase()}</span></td></tr>
                        <tr><th>Detection Ratio</th><td><strong>${r.virustotal.detection_ratio || '0/0'}</strong></td></tr>
                        <tr><th>Malicious Engines</th><td style="color: #b91c1c; font-weight: bold;">${r.virustotal.detection_stats?.malicious || 0}</td></tr>
                        <tr><th>Suspicious Engines</th><td style="color: #f59e0b; font-weight: bold;">${r.virustotal.detection_stats?.suspicious || 0}</td></tr>
                        <tr><th>Clean Engines</th><td style="color: #10b981; font-weight: bold;">${r.virustotal.detection_stats?.harmless || 0}</td></tr>
                        <tr><th>Total Engines</th><td><strong>${r.virustotal.detection_stats?.total_engines || 0}</strong></td></tr>
                        <tr><th>Reputation Score</th><td><strong>${r.virustotal.reputation !== undefined ? r.virustotal.reputation : '—'}</strong></td></tr>
                    </table>
                </div>
                ` : `<p class="fallback-text">VirusTotal data not available.</p>`}
            </div>
        </div>

        <!-- Email Harvesting & OSINT -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">✉️ Email Harvesting & OSINT</h3>
                ${data.is_domain ? getStatusLabel(r.email_gather) : '<span class="status-badge skipped">SKIPPED</span>'}
            </div>
            ${_emailHarvestingCard(r.email_gather || {}, data.is_domain)}
        </div>
`
}

const HTTP_AVAIL_OVERALL_STYLES = {
  https_ok: { label: 'Accessible (HTTPS)', bg: '#f0fdfa', border: '#99f6e4', color: '#0f766e' },
  no_forced_https: { label: 'Accessible — HTTPS Not Enforced', bg: '#fffbeb', border: '#fde68a', color: '#92400e' },
  http_only: { label: 'HTTP Only — HTTPS Unavailable', bg: '#fffbeb', border: '#fde68a', color: '#92400e' },
  not_accessible: { label: 'Not Accessible', bg: '#fef2f2', border: '#fecaca', color: '#b91c1c' },
  blocked_by_waf: { label: 'Blocked by WAF/Bot Protection', bg: '#fffbeb', border: '#fde68a', color: '#92400e' },
}

function _httpAvailabilityCard(label, result) {
  if (!result) return ''
  const badgeLabel = result.blocked_by_waf ? 'WAF Challenge'
    : result.weak_tls_downgrade ? 'Accessible (Weak TLS)'
    : result.accessible ? 'Accessible' : 'Not Accessible'
  const badgeStyle = (result.blocked_by_waf || result.weak_tls_downgrade)
    ? 'background-color:#fffbeb;border-color:#fde68a;color:#92400e;'
    : result.accessible
      ? 'background-color:#f0fdfa;border-color:#99f6e4;color:#0f766e;'
      : 'background-color:#fef2f2;border-color:#fecaca;color:#b91c1c;'
  return `
  <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
          <span style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold;">${label} · Port ${result.port ?? '—'}</span>
          <span style="font-size: 9px; font-weight: 800; text-transform: uppercase; padding: 4px 10px; border-radius: 999px; border: 1px solid; ${badgeStyle}">${badgeLabel}</span>
      </div>
      ${result.blocked_by_waf ? `<p class="fallback-text" style="color: #92400e;">${result.waf_note || ''}</p>` : ''}
      ${result.weak_tls_downgrade ? `<p class="fallback-text" style="color: #92400e;">${result.weak_tls_note || ''}</p>` : ''}
      ${result.accessible ? `
      <table class="kv-table" style="font-size: 12px;">
          <tr><th style="width: 40%;">Status Code</th><td>${result.status_code ?? '—'}</td></tr>
          <tr><th>HTTP Version</th><td>${result.http_version || '—'}</td></tr>
          <tr><th>Response Time</th><td>${result.response_time_ms != null ? result.response_time_ms + 'ms' : '—'}</td></tr>
          ${result.redirects_to ? `<tr><th>Redirects To</th><td class="mono" style="word-break: break-all;">${result.redirects_to}</td></tr>` : ''}
          ${result.redirect_count > 0 ? `<tr><th>Redirect Hops</th><td>${result.redirect_count}</td></tr>` : ''}
          ${result.final_url ? `<tr><th>Final URL</th><td class="mono" style="word-break: break-all;">${result.final_url}</td></tr>` : ''}
          ${result.final_status_code ? `<tr><th>Final Status</th><td>${result.final_status_code}</td></tr>` : ''}
      </table>
      <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 10px;">
          ${result.weak_tls_downgrade ? `<span class="tag" style="background-color:#fffbeb;border-color:#fde68a;color:#92400e;">Weak TLS — Non-Standard Client Only</span>` : ''}
          ${result.http2_supported ? `<span class="tag tag-teal">HTTP/2 Supported (via ALPN)</span>` : ''}
          ${result.hsts ? `<span class="tag" style="background-color:#f0fdfa;border-color:#99f6e4;color:#0f766e;">HSTS: max-age=${result.hsts.max_age_seconds ?? '?'}${result.hsts.include_subdomains ? ' · subdomains' : ''}${result.hsts.preload ? ' · preload' : ''}</span>` : ''}
      </div>
      ` : `<p class="fallback-text">${result.error_message || 'Connection failed.'}</p>`}
  </div>
  `
}

export function buildScanReportBodyTwoPane(data) {
  const r = data.results || {}
  const geo = r.geo_ip || {}
  const dns = r.dns_records || {}
  const ssl = r.ssl_certificate || {}
  const tech = r.web_technologies || {}
  const headers = r.http_headers || {}
  const subdomains = r.subdomains || {}
  // See buildScanReportBody's dirEnum comment — same legacy-key fallback.
  const dirEnum = r.directories || r.directory_enum || {}
  const ports = r.port_scan || {}
  const abuseipdb = r.abuseipdb || {}
  const virustotal = r.virustotal || {}
  const httpAvail = r.http_availability || {}
  const shodan = r.shodan_intel || {}

  const isOk = isModuleOk
  const getStatusLabel = moduleStatusBadge

  // 'deep' and 'detailed' are full synonyms everywhere else in the app
  // (scan_config.py's SCAN_MODES, Results.jsx's own isDeep) — the
  // aggressive/reputation module nav items and findings below only make
  // sense to show when the scan actually ran them, which is exactly this
  // condition (matches Results.jsx line ~518).
  const isDeep = data.scan_mode === 'deep' || data.scan_mode === 'detailed'

  const sslDays = ssl.days_until_expiry
  let whoisDays = r.whois?.days_until_expiry
  if (whoisDays == null && r.whois?.expiration_date) {
    const exp = new Date(r.whois.expiration_date)
    if (!isNaN(exp.getTime())) whoisDays = Math.ceil((exp.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
  }
  const techCount = Object.values(tech.technologies || {}).flat().length
  const headersCount = Object.keys(headers.security_headers_present || {}).length
  const subdomainsCount = subdomains.count || 0
  const dnsTypesCount = Object.keys(dns.records_by_type || {}).length
  const cloudDetected = r.cloud_provider?.cloud_detected
  const cmsDetected = r.cms_fingerprint?.cms_detected
  const wafDetected = r.waf_detect?.waf_detected
  const httpAvailOverall = httpAvail.overall
  const shodanVulnCount = shodan.vulns?.length || 0
  const shodanHasData = shodan.has_data !== false
  const emailFoundCount = r.email_gather?.total_found ?? r.email_gather?.emails?.length ?? 0
  const dirFoundCount = dirEnum.paths_found ?? dirEnum.found?.length ?? 0
  const reputationFlagged = (abuseipdb.abuse_confidence_score > 0) || (virustotal.detection_stats?.malicious > 0)

  // Findings (Overview pane) and navItems (sidebar) below are kept in
  // exact parity with Results.jsx's own `findings`/`MODULE_NAV` arrays —
  // this export previously only had 8 of the 15 findings and 10 of the 18
  // sidebar modules, silently dropping http_availability, shodan_intel,
  // port_scan, directories, reverse_dns, reputation (abuseipdb+virustotal)
  // and email_gather from every downloaded report.
  const findings = [
    {
      pane: 'ssl', icon: '🔑', label: 'SSL Certificate',
      value: sslDays != null ? `${sslDays} days remaining` : 'Not available',
      tone: sslDays == null ? 'neutral' : sslDays < 14 ? 'danger' : sslDays < 30 ? 'warning' : 'good',
    },
    data.is_domain && {
      pane: 'whois', icon: '📄', label: 'Domain Expiry',
      value: whoisDays != null ? `${whoisDays} days remaining` : 'Not available',
      tone: whoisDays == null ? 'neutral' : whoisDays < 30 ? 'danger' : whoisDays < 90 ? 'warning' : 'good',
    },
    {
      pane: 'headers', icon: '🛡️', label: 'Security Headers',
      value: `${headersCount} active headers`,
      tone: headersCount >= 5 ? 'good' : headersCount >= 2 ? 'warning' : 'danger',
    },
    {
      pane: 'waf', icon: '🛡️', label: 'WAF Protection',
      value: wafDetected ? (r.waf_detect.waf_name || 'WAF Detected') : 'No WAF detected',
      tone: wafDetected ? 'good' : 'neutral',
    },
    {
      pane: 'http_availability', icon: '📶', label: 'HTTP Availability',
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
      pane: 'shodan_intel', icon: '📡', label: 'Shodan Intel',
      value: shodanVulnCount > 0 ? `${shodanVulnCount} known CVEs` : shodanHasData ? 'No known CVEs' : 'Not available',
      tone: shodanVulnCount > 0 ? 'danger' : shodanHasData ? 'good' : 'neutral',
    },
    {
      pane: 'geoip', icon: '📍', label: 'GeoIP Location',
      value: (geo.city && geo.country) ? `${geo.city}, ${geo.country}` : (geo.country || geo.city || 'Not available'),
      tone: 'neutral',
    },
    {
      pane: 'tech', icon: '🛠️', label: 'Web Technologies',
      value: techCount > 0 ? `${techCount} identified` : 'None identified',
      tone: 'neutral',
    },
    isDeep && data.is_domain && {
      pane: 'subdomains', icon: '📁', label: 'Subdomains',
      value: subdomainsCount > 0 ? `${subdomainsCount} discovered` : 'None found',
      tone: 'neutral',
    },
    isDeep && {
      pane: 'cloud', icon: '☁️', label: 'Cloud Provider',
      value: cloudDetected ? r.cloud_provider.provider : 'Self-hosted / non-cloud',
      tone: 'neutral',
    },
    {
      pane: 'cms', icon: '🧩', label: 'CMS Platform',
      value: cmsDetected ? r.cms_fingerprint.cms_name : 'No known CMS',
      tone: 'neutral',
    },
    isDeep && data.is_domain && {
      pane: 'email_gather', icon: '✉️', label: 'Email Harvesting',
      value: emailFoundCount > 0 ? `${emailFoundCount} discovered` : 'None found',
      tone: 'neutral',
    },
    isDeep && {
      pane: 'ports', icon: '🖥️', label: 'Open Ports',
      value: ports.open_port_count > 0 ? `${ports.open_port_count} open` : 'None found',
      tone: ports.open_port_count > 0 ? 'warning' : 'good',
    },
    isDeep && {
      pane: 'directories', icon: '📂', label: 'Directory Enum',
      value: dirFoundCount > 0 ? `${dirFoundCount} discovered` : 'None found',
      tone: 'neutral',
    },
    isDeep && {
      pane: 'reputation', icon: '⚠️', label: 'IP Reputation',
      value: reputationFlagged ? 'Flagged by threat intel' : 'Clean',
      tone: reputationFlagged ? 'danger' : 'good',
    },
  ].filter(Boolean)

  const navItems = [
    { pane: 'dns', icon: '🌐', label: 'DNS Records', color: 'blue', domainOnly: true, badge: dnsTypesCount > 0 ? String(dnsTypesCount) : null },
    { pane: 'whois', icon: '📄', label: 'WHOIS Registry', color: 'slate', domainOnly: true },
    { pane: 'ssl', icon: '🔒', label: 'SSL Certificate', color: 'teal', badge: sslDays != null ? `${sslDays}d` : null },
    { pane: 'geoip', icon: '📍', label: 'GeoIP Location', color: 'blue' },
    { pane: 'tech', icon: '🛠️', label: 'Web Technologies', color: 'amber', badge: techCount > 0 ? String(techCount) : null },
    { pane: 'headers', icon: '🛡️', label: 'Security Headers', color: 'cyan', badge: headersCount > 0 ? String(headersCount) : null },
    { pane: 'http_availability', icon: '📶', label: 'HTTP Availability', color: 'teal' },
    { pane: 'shodan_intel', icon: '📡', label: 'Shodan Intel', color: 'indigo' },
    { pane: 'waf', icon: '🛡️', label: 'WAF Detection', color: 'red', badge: wafDetected ? '!' : null },
    { pane: 'ports', icon: '🖥️', label: 'Ports & Services', color: 'indigo', deepOnly: true, badge: ports.open_port_count > 0 ? String(ports.open_port_count) : null },
    { pane: 'directories', icon: '📂', label: 'Directory Enum', color: 'emerald', deepOnly: true, badge: dirFoundCount > 0 ? String(dirFoundCount) : null },
    { pane: 'reverse_dns', icon: '🌐', label: 'Reverse DNS', color: 'violet', deepOnly: true },
    { pane: 'reputation', icon: '⚠️', label: 'IP Reputation', color: 'orange', deepOnly: true },
    { pane: 'email_gather', icon: '✉️', label: 'Email Harvesting', color: 'rose', deepOnly: true, domainOnly: true, badge: emailFoundCount > 0 ? String(emailFoundCount) : null },
    { pane: 'subdomains', icon: '📁', label: 'Subdomains', color: 'purple', deepOnly: true, domainOnly: true, badge: subdomainsCount > 0 ? String(subdomainsCount) : null },
    { pane: 'cloud', icon: '☁️', label: 'Cloud Provider', color: 'sky', deepOnly: true },
    { pane: 'cms', icon: '🧩', label: 'CMS Detection', color: 'fuchsia' },
  ].filter(item => (!item.domainOnly || data.is_domain) && (!item.deepOnly || isDeep))

  return `
        <!-- Target Panel -->
        <div class="target-panel">
            <div class="target-panel-label">Diagnostics Panel</div>
            <h1 class="target-panel-name">${data.target}</h1>
            <div class="target-panel-meta">
                ${data.resolved_ip && data.resolved_ip !== data.target ? `<span>Resolved IP: ${data.resolved_ip}</span><span class="sep">|</span>` : ''}
                <span>Duration: ${data.scan_duration_seconds ? data.scan_duration_seconds + 's' : 'N/A'}</span>
                <span class="sep">|</span>
                <span class="mode-tag">${data.scan_mode === 'fast' ? 'Standard Scan' : 'Deep Scan'}</span>
            </div>
        </div>

        <div class="report-two-pane">
            <!-- Sidebar -->
            <div class="report-sidebar">
                <div class="report-sidebar-title">Modules</div>
                <button class="sidebar-btn active" data-pane="overview" data-color="teal" onclick="showReportPane('overview', this)">📊 Overview</button>
                ${navItems.map(item => `
                <button class="sidebar-btn" data-pane="${item.pane}" data-color="${item.color}" onclick="showReportPane('${item.pane}', this)">
                    ${item.icon} ${item.label}
                    ${item.badge ? `<span class="nav-badge">${item.badge}</span>` : ''}
                </button>
                `).join('')}
            </div>

            <!-- Content -->
            <div class="report-content">
                <!-- Overview Pane -->
                <div id="pane-overview" class="content-pane">
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="label">Target</div>
                            <div class="value">${data.target}</div>
                        </div>
                        <div class="stat-box">
                            <div class="label">Scan Duration</div>
                            <div class="value">${data.scan_duration_seconds}s</div>
                        </div>
                        <div class="stat-box">
                            <div class="label">Resolved IP</div>
                            <div class="value">${data.resolved_ip}</div>
                        </div>
                    </div>
                    <div class="findings-title">Key Findings</div>
                    <div class="findings-grid">
                        ${findings.map(f => `
                        <button class="finding-card finding-${f.tone}" onclick="showReportPane('${f.pane}', document.querySelector('[data-pane=&quot;${f.pane}&quot;]'))">
                            <div class="f-label">${f.icon} ${f.label}</div>
                            <div class="f-value">${f.value}</div>
                        </button>
                        `).join('')}
                    </div>
                </div>

                <!-- DNS Records -->
                ${data.is_domain ? `
                <div id="pane-dns" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🌐 DNS Records</h3>
                        ${getStatusLabel(r.dns_records)}
                    </div>
                    ${isOk(r.dns_records) && dns.records_by_type ? `
                    <div class="dns-grid">
                        ${["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"].map(type => {
                          const result = dns.records_by_type[type]
                          if (!result) return ''
                          const recs = result.records || []
                          return `
                                        <div class="dns-record-block" style="margin-bottom: 15px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                                            <div style="font-family: monospace; font-size: 11px; font-weight: bold; color: #ea580c; margin-bottom: 6px;">${type}</div>
                                            ${recs.length === 0 ? `
                                            <div class="mono" style="font-size: 11px; color: #94a3b8; font-style: italic;">No ${type} records configured.</div>
                                            ` : `
                                            ${typeof recs[0] !== 'object' ? `
                                            <table style="border: 1px solid #e2e8f0; border-radius: 4px; font-size: 11px; width: 100%; border-collapse: collapse;">
                                                <thead><tr style="background-color: #f1f5f9;"><th style="width: 20%; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Type</th><th style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Record / Address</th></tr></thead>
                                                <tbody>
                                                    ${recs.map(rec => `<tr><td style="font-weight: bold; color: #0284c7; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${type}</td><td class="mono" style="word-break: break-all; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${rec}</td></tr>`).join('')}
                                                </tbody>
                                            </table>
                                            ` : `
                                            <table style="border: 1px solid #e2e8f0; border-radius: 4px; font-size: 11px; width: 100%; border-collapse: collapse;">
                                                <thead><tr style="background-color: #f1f5f9;"><th style="width: 20%; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left;">Type</th>${Object.keys(recs[0]).map(k => `<th style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; text-align: left; text-transform: uppercase;">${k.replace(/_/g, ' ')}</th>`).join('')}</tr></thead>
                                                <tbody>
                                                    ${recs.map(rec => `<tr><td style="font-weight: bold; color: #0284c7; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${type}</td>${Object.keys(recs[0]).map(k => `<td class="mono" style="word-break: break-all; padding: 6px 10px; border-bottom: 1px solid #f1f5f9;">${String(rec[k])}</td>`).join('')}</tr>`).join('')}
                                                </tbody>
                                            </table>
                                            `}
                                            `}
                                        </div>
                                        `
                        }).join('')}
                    </div>
                    ` : `<p class="fallback-text">No DNS records resolved.</p>`}
                </div>
                </div>
                ` : ''}

                <!-- WHOIS -->
                ${data.is_domain ? `
                <div id="pane-whois" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📄 Domain Registration (WHOIS)</h3>
                        ${getStatusLabel(r.whois)}
                    </div>
                    ${isOk(r.whois) ? `
                    <table class="kv-table">
                        <tr><th style="width: 30%;">Registrar Host</th><td>${r.whois.registrar || '—'}</td></tr>
                        <tr><th>Registrar IANA ID</th><td>${r.whois.registrar_iana_id || '—'}</td></tr>
                        <tr><th>Registrar Abuse Email</th><td>${r.whois.registrar_abuse_email || '—'}</td></tr>
                        <tr><th>Registrar Abuse Phone</th><td>${r.whois.registrar_abuse_phone || '—'}</td></tr>
                        <tr><th>Registered Date</th><td>${r.whois.creation_date ? new Date(r.whois.creation_date).toLocaleDateString() : '—'}</td></tr>
                        <tr><th>Expiration Date</th><td>${r.whois.expiration_date ? new Date(r.whois.expiration_date).toLocaleDateString() : '—'}</td></tr>
                        <tr><th>Last Modified Date</th><td>${r.whois.updated_date ? new Date(r.whois.updated_date).toLocaleDateString() : '—'}</td></tr>
                        <tr><th>Days Until Expiry</th><td>${r.whois.days_until_expiry != null ? `${r.whois.days_until_expiry} days` : '—'}</td></tr>
                        <tr><th>Expiry Status</th><td>${r.whois.expiry_status || '—'}</td></tr>
                        <tr><th>Registrant Name</th><td>${r.whois.registrant_name || '—'}</td></tr>
                        <tr><th>Registrant Org</th><td>${r.whois.registrant_org || r.whois.org || '—'}</td></tr>
                        <tr><th>Registrant Country</th><td>${r.whois.country || '—'}</td></tr>
                        <tr><th>Registrant State</th><td>${r.whois.state || '—'}</td></tr>
                        <tr><th>Registrant City</th><td>${r.whois.city || '—'}</td></tr>
                        <tr><th>DNSSEC Status</th><td>${r.whois.dnssec || '—'}</td></tr>
                        <tr><th>Name Servers</th><td>
                            ${r.whois.name_servers && r.whois.name_servers.length > 0 ?
                            `<div style="display: flex; flex-direction: column; gap: 4px;">
                                ${r.whois.name_servers.map(ns => `<span class="mono" style="font-size: 11px;">${ns}</span>`).join('')}
                            </div>` : '—'}
                        </td></tr>
                    </table>
                    ` : `<p class="fallback-text">WHOIS details not available.</p>`}
                </div>
                </div>
                ` : ''}

                <!-- SSL Certificate -->
                <div id="pane-ssl" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🔒 SSL/TLS Security Certificate</h3>
                        ${getStatusLabel(r.ssl_certificate)}
                    </div>
                    ${isOk(r.ssl_certificate) ? `
                    ${ssl.days_until_expiry !== null && ssl.days_until_expiry !== undefined ? `
                    <div style="font-size: 11px; font-weight: bold; margin-bottom: 15px; padding: 8px; border: 1px solid ${ssl.days_until_expiry < 0 ? '#fecaca' : '#bbf7d0'}; border-radius: 6px; background-color: ${ssl.days_until_expiry < 0 ? '#fef2f2' : '#f0fdf4'}; color: ${ssl.days_until_expiry < 0 ? '#b91c1c' : '#15803d'}; display: inline-block;">
                        Status: ${ssl.days_until_expiry < 0 ? `Expired ${-ssl.days_until_expiry} days ago` : `Expires in ${ssl.days_until_expiry} days`}
                    </div>
                    ` : ''}
                    <table class="kv-table" style="margin-bottom: 20px;">
                        <tr><th style="width: 30%;">Common Name (CN)</th><td><strong>${ssl.subject_common_name || 'N/A'}</strong></td></tr>
                        <tr><th>Certificate Issuer</th><td>${ssl.issuer_common_name || 'N/A'}</td></tr>
                        <tr><th>Issuer Org</th><td>${ssl.issuer_organization || 'N/A'}</td></tr>
                        <tr><th>Valid From</th><td>${ssl.valid_from || 'N/A'}</td></tr>
                        <tr><th>Valid Until</th><td>${ssl.valid_until || 'N/A'}</td></tr>
                        <tr><th>Negotiated Protocol</th><td class="mono">${ssl.protocol || 'N/A'}</td></tr>
                        <tr><th>Negotiated Cipher</th><td class="mono">${ssl.cipher_suite || 'N/A'}</td></tr>
                    </table>
                    ${ssl.subject_alternative_names && ssl.subject_alternative_names.length > 0 ? `
                    <div style="margin-top: 15px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: #115e59; margin-bottom: 10px;">Alternative Subject Names (SANs)</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                            ${ssl.subject_alternative_names.map(san => `
                            <span style="font-size: 10px; background-color: white; border: 1px solid #ccfbf1; padding: 4px 8px; border-radius: 4px; color: #115e59; font-weight: bold; font-family: monospace;">${san}</span>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    ` : `<p class="fallback-text">No SSL certificate details fetched.</p>`}
                </div>
                </div>

                <!-- GeoIP -->
                <div id="pane-geoip" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📍 Geolocation & Host Info</h3>
                        ${getStatusLabel(r.geo_ip)}
                    </div>
                    ${isOk(r.geo_ip) ? `
                    <table class="kv-table">
                        <tr><th style="width: 30%;">IP Address</th><td>${geo.ip || 'N/A'}</td></tr>
                        <tr><th>Country</th><td>${geo.country ? `${geo.country} (${geo.country_code || 'N/A'})` : 'N/A'}</td></tr>
                        <tr><th>Region / State</th><td>${geo.region || 'N/A'}</td></tr>
                        <tr><th>City</th><td>${geo.city || 'N/A'}</td></tr>
                        <tr><th>Coordinates</th><td>${geo.latitude && geo.longitude ? `${geo.latitude}, ${geo.longitude}` : 'N/A'}</td></tr>
                        <tr><th>Timezone</th><td>${geo.timezone || 'N/A'}</td></tr>
                        <tr><th>ISP Provider</th><td>${geo.isp || 'N/A'}</td></tr>
                        <tr><th>Organization</th><td>${geo.organization || geo.org || 'N/A'}</td></tr>
                        <tr><th>ASN Number</th><td>${geo.asn || 'N/A'}</td></tr>
                        <tr><th>Hosting Server</th><td>${geo.is_hosting ? 'Yes (Cloud/Server)' : 'No'}</td></tr>
                        <tr><th>Proxy / VPN Network</th><td>${geo.is_proxy ? 'Yes' : 'No'}</td></tr>
                    </table>
                    ` : `<p class="fallback-text">No geolocation details available for this host.</p>`}
                </div>
                </div>

                <!-- Web Technologies -->
                <div id="pane-tech" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🛠️ Web Application Stack</h3>
                        ${getStatusLabel(r.web_technologies)}
                    </div>
                    ${isOk(r.web_technologies) && tech.technologies ? `
                    ${tech.weak_tls_downgrade ? `<p class="fallback-text" style="color: #92400e;">${tech.weak_tls_note || ''}</p>` : ''}
                    <table class="kv-table" style="margin-bottom: 15px;">
                        <tr><th style="width: 30%;">Server Header</th><td class="mono">${tech.meta?.server || '—'}</td></tr>
                        <tr><th>Powered By</th><td class="mono">${tech.meta?.powered_by || '—'}</td></tr>
                        <tr><th>Content Type</th><td class="mono">${tech.meta?.content_type || '—'}</td></tr>
                    </table>
                    <div>
                        <h4 style="font-size: 12px; text-transform: uppercase; color: #0f172a; margin-bottom: 8px;">Detected Component Stack</h4>
                        ${Object.entries(tech.technologies).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            ${Object.entries(tech.technologies).map(([cat, list]) => `
                            <div>
                                <div style="font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: bold; margin-bottom: 4px;">${cat.replace('_', ' ')}</div>
                                <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                                    ${list.map(t => `<span class="tag tag-teal" style="font-weight: bold;">${t}</span>`).join('')}
                                </div>
                            </div>
                            `).join('')}
                        </div>
                        ` : '<p style="font-size: 11px; font-style: italic; color: #64748b;">No signature-matched web framework signatures detected.</p>'}
                    </div>
                    ` : `<p class="fallback-text">No web application stack scan was collected.</p>`}
                </div>
                </div>

                <!-- Security Headers -->
                <div id="pane-headers" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🛡️ Security Headers Check</h3>
                        ${getStatusLabel(r.http_headers)}
                    </div>
                    ${isOk(r.http_headers) ? `
                    <div class="grid-2">
                        <div>
                            <h4 style="font-size: 11px; text-transform: uppercase; color: #166534; margin-bottom: 8px;">Present Security Headers</h4>
                            ${headers.security_headers_present && Object.keys(headers.security_headers_present).length > 0 ? `
                            <div style="display: flex; flex-direction: column; gap: 6px;">
                                ${Object.entries(headers.security_headers_present).map(([h, val]) => `
                                <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 6px 10px; border-radius: 6px; font-size: 11px;">
                                    <strong style="color: #166534;">${h}</strong>
                                    <div class="mono" style="margin-top: 4px; font-size: 10px; word-break: break-all;">${val}</div>
                                </div>
                                `).join('')}
                            </div>
                            ` : '<p style="font-size: 11px; font-style: italic; color: #166534;">None of the target security headers were found.</p>'}
                        </div>
                        <div>
                            <h4 style="font-size: 11px; text-transform: uppercase; color: #991b1b; margin-bottom: 8px;">Missing Security Headers</h4>
                            ${headers.security_headers_missing && headers.security_headers_missing.length > 0 ? `
                            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                                ${headers.security_headers_missing.map(h => `
                                <span class="tag" style="background-color: #fef2f2; border-color: #fee2e2; color: #991b1b; padding: 4px 8px; font-weight: bold;">
                                    ${h}
                                </span>
                                `).join('')}
                            </div>
                            ` : '<p style="font-size: 11px; font-style: italic; color: #166534;">All standard security headers are present!</p>'}
                        </div>
                    </div>
                    ` : `<p class="fallback-text">No security headers analysis was collected.</p>`}
                </div>
                </div>

                <!-- HTTP Availability -->
                <div id="pane-http_availability" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📶 HTTP/HTTPS Accessibility</h3>
                        ${getStatusLabel(r.http_availability)}
                    </div>
                    ${isOk(r.http_availability) ? `
                    ${(() => {
                      const style = HTTP_AVAIL_OVERALL_STYLES[httpAvail.overall] || { label: httpAvail.overall || 'Unknown', bg: '#f8fafc', border: '#e2e8f0', color: '#334155' }
                      return `<div style="display: inline-block; padding: 8px 14px; border-radius: 8px; font-weight: bold; margin-bottom: 15px; border: 1px solid ${style.border}; background-color: ${style.bg}; color: ${style.color};">${style.label}</div>`
                    })()}
                    ${httpAvail.summary ? `<p style="font-size: 12px; color: #64748b; margin-bottom: 15px;">${httpAvail.summary}</p>` : ''}
                    ${_httpAvailabilityCard('HTTP', httpAvail.http)}
                    ${_httpAvailabilityCard('HTTPS', httpAvail.https)}
                    ` : `<p class="fallback-text">No accessibility data available.</p>`}
                </div>
                </div>

                <!-- Shodan Intel -->
                <div id="pane-shodan_intel" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📡 Shodan Intel</h3>
                        ${getStatusLabel(r.shodan_intel)}
                    </div>
                    ${isOk(r.shodan_intel) && shodan.has_data !== false ? `
                    <div style="display: flex; align-items: baseline; gap: 10px; margin-bottom: 18px;">
                        <div style="font-size: 32px; font-weight: 800; font-family: monospace; color: ${(shodan.vulns?.length || 0) > 0 ? '#b91c1c' : '#0f766e'};">${shodan.vulns?.length || 0}</div>
                        <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; font-weight: bold;">known CVEs on detected services</div>
                    </div>
                    <div style="margin-bottom: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: #64748b; margin-bottom: 8px;">Threat/Infra Tags (${(shodan.tags || []).length})</h4>
                        ${(shodan.tags || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${shodan.tags.map(t => `<div><span class="tag" style="background-color: #eef2ff; border-color: #c7d2fe; color: #4338ca;">${t.tag}</span>${t.description ? ` <span style="font-size: 10px; color: #64748b;">${t.description}</span>` : ''}</div>`).join('')}
                        </div>
                        ` : `<p class="fallback-text">None assigned.</p>`}
                    </div>
                    <div style="margin-bottom: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: #64748b; margin-bottom: 8px;">Open Ports (${(shodan.ports || []).length})</h4>
                        ${(shodan.ports || []).length > 0 ? `
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${shodan.ports.map(p => `<span class="tag">${p.port}${p.service ? ` · ${p.service}` : ''}</span>`).join('')}
                        </div>
                        ` : `<p class="fallback-text">No open ports on record.</p>`}
                    </div>
                    <div style="margin-bottom: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: #64748b; margin-bottom: 8px;">Associated Hostnames (${(shodan.hostnames || []).length})</h4>
                        ${(shodan.hostnames || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            ${shodan.hostnames.map(h => `<div class="mono" style="font-size: 11px; background: #f8fafc; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; word-break: break-all;">${h}</div>`).join('')}
                        </div>
                        ` : `<p class="fallback-text">None on record.</p>`}
                    </div>
                    <div style="margin-bottom: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: #64748b; margin-bottom: 8px;">Detected Software (${(shodan.cpes || []).length})</h4>
                        ${(shodan.cpes || []).length > 0 ? `
                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            ${shodan.cpes.map(c => `<div class="mono" style="font-size: 11px; background: #f8fafc; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; word-break: break-all;">${[c.vendor, c.product].filter(Boolean).join(' ').replace(/_/g, ' ') || c.raw}${c.version ? ` v${c.version}` : ''}${c.type ? ` (${c.type})` : ''}</div>`).join('')}
                        </div>
                        ` : `<p class="fallback-text">No software/version fingerprinted.</p>`}
                    </div>
                    <div style="border-top: 1px solid #e2e8f0; padding-top: 15px;">
                        <h4 style="font-size: 10px; text-transform: uppercase; color: ${(shodan.vulns?.length || 0) > 0 ? '#b91c1c' : '#64748b'}; margin-bottom: 8px;">Known Vulnerabilities (${(shodan.vulns || []).length})</h4>
                        ${(shodan.vulns || []).length > 0 ? `
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${shodan.vulns.map(v => `<a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" class="tag" style="background-color: #fef2f2; border-color: #fecaca; color: #b91c1c; text-decoration: none;">${v}</a>`).join('')}
                        </div>
                        ` : `<p class="fallback-text">No known CVEs tied to detected services.</p>`}
                    </div>
                    ` : isOk(r.shodan_intel) ? `<p class="fallback-text">${shodan.note || 'No Shodan data available for this IP.'}</p>` : `<p class="fallback-text">Shodan intel not available.</p>`}
                </div>
                </div>

                <!-- WAF Detection -->
                <div id="pane-waf" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🛡️ Web Application Firewall</h3>
                        ${getStatusLabel(r.waf_detect)}
                    </div>
                    ${isOk(r.waf_detect) ? `
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div style="background-color: ${r.waf_detect.waf_detected ? '#fef2f2' : '#f0fdf4'}; color: ${r.waf_detect.waf_detected ? '#b91c1c' : '#15803d'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.waf_detect.waf_detected ? '#fecaca' : '#bbf7d0'};">
                            ${r.waf_detect.waf_detected ? r.waf_detect.waf_name : 'No WAF Detected'}
                        </div>
                    </div>
                    ${r.waf_detect.waf_detected && r.waf_detect.all_detected && r.waf_detect.all_detected.length > 1 ? `
                    <p style="font-size: 12px; color: #64748b; margin-bottom: 15px;">Multiple WAF layers detected: ${r.waf_detect.all_detected.join(', ')}.</p>
                    ` : ''}
                    ${r.waf_detect.probes && r.waf_detect.probes.length > 0 ? `
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 8px;">Attack Probes</h4>
                    <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                        ${r.waf_detect.probes.map(p => `
                        <div style="border: 1px solid ${p.likely_blocked ? '#fecaca' : '#e2e8f0'}; background-color: ${p.likely_blocked ? '#fef2f2' : '#f8fafc'}; padding: 10px; border-radius: 8px; min-width: 120px;">
                            <div style="font-size: 9px; text-transform: uppercase; color: #64748b; margin-bottom: 4px;">${p.probe.replace(/_/g, ' ')}</div>
                            <div style="font-size: 18px; font-weight: bold; color: ${p.likely_blocked ? '#b91c1c' : '#0f172a'};">${p.status_code}</div>
                            <div style="font-size: 10px; font-weight: bold; color: ${p.likely_blocked ? '#ef4444' : '#10b981'}; text-transform: uppercase;">${p.likely_blocked ? 'Blocked' : 'Passed'}</div>
                        </div>
                        `).join('')}
                    </div>
                    ` : ''}
                    ` : `<p class="fallback-text">WAF detection not available.</p>`}
                </div>
                </div>

                <!-- Ports & Services -->
                <div id="pane-ports" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🖥️ Active Services & Ports</h3>
                        ${getStatusLabel(r.port_scan)}
                    </div>
                    ${_portsCard(ports)}
                </div>
                </div>

                <!-- Directory Enumeration -->
                <div id="pane-directories" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📂 Directory Enumeration</h3>
                        ${getStatusLabel(dirEnum)}
                    </div>
                    ${_directoryEnumCard(dirEnum)}
                </div>
                </div>

                <!-- Reverse DNS -->
                <div id="pane-reverse_dns" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🌐 Reverse DNS Pointer (PTR Record)</h3>
                        ${getStatusLabel(r.reverse_dns)}
                    </div>
                    ${r.reverse_dns && r.reverse_dns.status !== 'skipped' && r.reverse_dns.hostname ? `
                    <div class="mono" style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px;">
                        <div style="font-weight: bold; color: #0f172a;">${r.reverse_dns.hostname}</div>
                        ${r.reverse_dns.nslookup_resolver_hostname && r.reverse_dns.nslookup_resolver_hostname !== r.reverse_dns.hostname ? `
                        <div style="font-size: 10px; color: #64748b; margin-top: 4px;">
                            Comparing resolvers: Socket resolution resolved <strong>${r.reverse_dns.primary_resolver_hostname || '—'}</strong>, nslookup resolved <strong>${r.reverse_dns.nslookup_resolver_hostname}</strong>
                        </div>
                        ` : ''}
                    </div>
                    ` : `<p class="fallback-text">No PTR record found.</p>`}
                </div>
                </div>

                <!-- IP Reputation -->
                <div id="pane-reputation" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">⚠️ IP Reputation & Threat Intelligence</h3>
                        <div>
                            ${getStatusLabel(r.abuseipdb)} ${getStatusLabel(r.virustotal)}
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        ${isOk(r.abuseipdb) ? `
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px;">
                            <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; font-weight: bold;">AbuseIPDB Reputation</h4>
                            <table class="kv-table" style="font-size: 12px;">
                                <tr><th style="width: 50%;">IP Address</th><td class="mono" style="font-weight: bold;">${r.abuseipdb.ip || '—'}</td></tr>
                                <tr><th>Threat Level</th><td><span style="font-weight: bold; color: ${r.abuseipdb.threat_level === 'critical' ? '#b91c1c' : r.abuseipdb.threat_level === 'high' ? '#dc2626' : r.abuseipdb.threat_level === 'medium' ? '#f59e0b' : '#10b981'};">${(r.abuseipdb.threat_level || '—').toUpperCase()}</span></td></tr>
                                <tr><th>Abuse Confidence</th><td><strong style="color: ${r.abuseipdb.abuse_confidence_score > 75 ? '#b91c1c' : r.abuseipdb.abuse_confidence_score > 50 ? '#f59e0b' : '#10b981'};">${r.abuseipdb.abuse_confidence_score || 0}%</strong></td></tr>
                                <tr><th>Total Reports</th><td><strong>${r.abuseipdb.total_reports || 0}</strong></td></tr>
                                <tr><th>Country</th><td>${r.abuseipdb.country_name ? `${r.abuseipdb.country_name} (${r.abuseipdb.country_code})` : '—'}</td></tr>
                                <tr><th>ISP/Organization</th><td>${r.abuseipdb.isp || '—'}</td></tr>
                                <tr><th>Tor Network</th><td>${r.abuseipdb.is_tor ? '<span style="color: #b91c1c; font-weight: bold;">YES (Exit Node)</span>' : 'No'}</td></tr>
                                <tr><th>VPN/Proxy</th><td>${r.abuseipdb.is_proxy ? '<span style="color: #f59e0b; font-weight: bold;">YES</span>' : 'No'}</td></tr>
                                <tr><th>Whitelisted</th><td>${r.abuseipdb.is_whitelisted ? '<span style="color: #10b981; font-weight: bold;">YES</span>' : 'No'}</td></tr>
                            </table>
                        </div>
                        ` : `<p class="fallback-text">AbuseIPDB reputation data not available.</p>`}
                        ${isOk(r.virustotal) ? `
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px;">
                            <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; font-weight: bold;">VirusTotal Scan Results</h4>
                            <table class="kv-table" style="font-size: 12px;">
                                <tr><th style="width: 50%;">Target</th><td class="mono" style="font-weight: bold;">${r.virustotal.target || '—'}</td></tr>
                                <tr><th>Threat Level</th><td><span style="font-weight: bold; color: ${r.virustotal.threat_level === 'critical' ? '#b91c1c' : r.virustotal.threat_level === 'high' ? '#dc2626' : r.virustotal.threat_level === 'medium' ? '#f59e0b' : '#10b981'};">${(r.virustotal.threat_level || '—').toUpperCase()}</span></td></tr>
                                <tr><th>Detection Ratio</th><td><strong>${r.virustotal.detection_ratio || '0/0'}</strong></td></tr>
                                <tr><th>Malicious Engines</th><td style="color: #b91c1c; font-weight: bold;">${r.virustotal.detection_stats?.malicious || 0}</td></tr>
                                <tr><th>Suspicious Engines</th><td style="color: #f59e0b; font-weight: bold;">${r.virustotal.detection_stats?.suspicious || 0}</td></tr>
                                <tr><th>Clean Engines</th><td style="color: #10b981; font-weight: bold;">${r.virustotal.detection_stats?.harmless || 0}</td></tr>
                                <tr><th>Total Engines</th><td><strong>${r.virustotal.detection_stats?.total_engines || 0}</strong></td></tr>
                                <tr><th>Reputation Score</th><td><strong>${r.virustotal.reputation !== undefined ? r.virustotal.reputation : '—'}</strong></td></tr>
                            </table>
                        </div>
                        ` : `<p class="fallback-text">VirusTotal data not available.</p>`}
                    </div>
                </div>
                </div>

                <!-- Email Harvesting -->
                ${data.is_domain ? `
                <div id="pane-email_gather" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">✉️ Email Harvesting & OSINT</h3>
                        ${getStatusLabel(r.email_gather)}
                    </div>
                    ${_emailHarvestingCard(r.email_gather || {}, data.is_domain)}
                </div>
                </div>
                ` : ''}

                <!-- Subdomains -->
                ${data.is_domain ? `
                <div id="pane-subdomains" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📁 Subdomains Index</h3>
                        ${getStatusLabel(r.subdomains)}
                    </div>
                    ${_subdomainsCard(subdomains, true)}
                </div>
                </div>
                ` : ''}

                <!-- Cloud Provider -->
                <div id="pane-cloud" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">☁️ Cloud Provider</h3>
                        ${getStatusLabel(r.cloud_provider)}
                    </div>
                    ${isOk(r.cloud_provider) ? `
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div style="background-color: ${r.cloud_provider.cloud_detected ? '#eff6ff' : '#f8fafc'}; color: ${r.cloud_provider.cloud_detected ? '#1d4ed8' : '#475569'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.cloud_provider.cloud_detected ? '#bfdbfe' : '#e2e8f0'};">
                            ${r.cloud_provider.cloud_detected ? r.cloud_provider.provider : 'Self-Hosted / Non-Cloud'}
                        </div>
                        ${r.cloud_provider.confidence ? `<span class="tag">${r.cloud_provider.confidence} confidence</span>` : ''}
                    </div>
                    <table class="kv-table" style="font-size: 12px;">
                        <tr><th style="width: 40%;">Detection Method</th><td><span class="mono">${r.cloud_provider.method || '—'}</span></td></tr>
                        ${r.cloud_provider.ranges_checked !== undefined ? `<tr><th>CIDR Ranges Checked</th><td>${r.cloud_provider.ranges_checked.toLocaleString()}</td></tr>` : ''}
                        ${r.cloud_provider.asn_org ? `<tr><th>ASN Organization</th><td>${r.cloud_provider.asn_org}</td></tr>` : ''}
                        ${r.cloud_provider.asn_isp ? `<tr><th>ISP Provider</th><td>${r.cloud_provider.asn_isp}</td></tr>` : ''}
                        ${r.cloud_provider.as_number ? `<tr><th>AS Number</th><td>${r.cloud_provider.as_number}</td></tr>` : ''}
                        ${r.cloud_provider.is_hosting !== undefined ? `<tr><th>Server Hosting</th><td>${r.cloud_provider.is_hosting ? 'Yes (Datacenter)' : 'No (Residential/Business)'}</td></tr>` : ''}
                    </table>
                    ` : `<p class="fallback-text">Cloud provider detection not available.</p>`}
                </div>
                </div>

                <!-- CMS Fingerprint -->
                <div id="pane-cms" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">🧩 CMS Fingerprint</h3>
                        ${getStatusLabel(r.cms_fingerprint)}
                    </div>
                    ${isOk(r.cms_fingerprint) ? `
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div style="background-color: ${r.cms_fingerprint.cms_detected ? '#fdf4ff' : '#f8fafc'}; color: ${r.cms_fingerprint.cms_detected ? '#a21caf' : '#475569'}; padding: 8px 12px; border-radius: 8px; font-weight: bold; border: 1px solid ${r.cms_fingerprint.cms_detected ? '#f5d0fe' : '#e2e8f0'};">
                            ${r.cms_fingerprint.cms_detected ? r.cms_fingerprint.cms_name : 'Custom / Non-CMS Site'}
                            ${r.cms_fingerprint.version ? `<span style="margin-left: 8px; font-size: 12px; color: #d946ef; font-family: monospace;">v${r.cms_fingerprint.version}</span>` : ''}
                        </div>
                    </div>
                    ` : `<p class="fallback-text">CMS fingerprinting not available.</p>`}
                </div>
                </div>
            </div>
        </div>

        <script>
            function showReportPane(id, btn) {
                document.querySelectorAll('.content-pane').forEach(function(p) { p.hidden = true; });
                var target = document.getElementById('pane-' + id);
                if (target) target.hidden = false;
                document.querySelectorAll('.sidebar-btn').forEach(function(b) { b.classList.remove('active'); });
                if (btn) btn.classList.add('active');
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        </script>
`
}

function _escapeHtmlForBatch(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

/**
 * Builds an HTML report for a batch of full scans (up to 20 user-typed
 * targets, each a full Standard/Deep scan) — one <details> block per
 * target, generalizing the inline pattern BatchScanResults.jsx uses for
 * subdomain batches. Picks buildScanReportBody vs buildScanReportBodyTwoPane
 * per item the same way Results.jsx does (data.scan_mode === 'fast'/'deep'
 * uses the two-pane builder), since full-scan-batch results are always one
 * of those two modes.
 */
export function buildBatchScanReportBody(batchResults, { title = 'Batch Full Scan Report', subtitle = 'Batch Full Scan Report' } = {}) {
    const rows = batchResults.results || []

    const sections = rows.map((item) => {
        const statusClass = item.status === 'completed' ? 'ok' : item.status === 'failed' ? 'error' : item.status === 'timeout' ? 'partial' : 'skipped'

        let body
        if (item.scan_result) {
            const usesTwoPane = item.scan_result.scan_mode === 'fast' || item.scan_result.scan_mode === 'deep' || item.scan_result.scan_mode === 'detailed'
            body = usesTwoPane ? buildScanReportBodyTwoPane(item.scan_result) : buildScanReportBody(item.scan_result)
        } else if (item.error) {
            body = `<div class="error-box">${_escapeHtmlForBatch(item.error)}</div>`
        } else {
            body = '<p class="fallback-text">No scan data was captured for this target.</p>'
        }

        return `
        <details class="subdomain-block">
          <summary>
            <span class="subdomain-name">${_escapeHtmlForBatch(item.target)}</span>
            <span class="status-badge ${statusClass}">${_escapeHtmlForBatch(item.status).toUpperCase()}</span>
            ${item.resolved_ips && item.resolved_ips.length ? `<span class="ip-list">IPs: ${_escapeHtmlForBatch(item.resolved_ips.join(', '))}</span>` : ''}
          </summary>
          <div class="subdomain-content">
            ${body}
          </div>
        </details>
      `
    }).join('')

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${_escapeHtmlForBatch(title)}</title>
<style>${SCAN_REPORT_STYLES}</style>
</head>
<body>
  <div class="container">
    <div class="header" style="background: linear-gradient(135deg, #0d9488 0%, #06b6d4 100%);">
      <div class="subtitle">${_escapeHtmlForBatch(subtitle)}</div>
      <h1>🧭 ${rows.length} Target${rows.length === 1 ? '' : 's'} Scanned</h1>
      <div class="meta-grid">
        <div class="meta-item">
          <span class="label">Total Targets</span>
          <span class="value">${batchResults.total_targets ?? rows.length}</span>
        </div>
        <div class="meta-item">
          <span class="label">Completed</span>
          <span class="value">${batchResults.completed_scans ?? ''}</span>
        </div>
        <div class="meta-item">
          <span class="label">Failed</span>
          <span class="value">${batchResults.failed_scans ?? ''}</span>
        </div>
        <div class="meta-item">
          <span class="label">Generated</span>
          <span class="value">${_escapeHtmlForBatch(new Date().toLocaleString())}</span>
        </div>
      </div>
    </div>
    ${sections}
  </div>
</body>
</html>`
}