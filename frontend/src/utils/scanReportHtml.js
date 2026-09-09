
export const SCAN_REPORT_STYLES = `
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            color: #1e293b;
            background: linear-gradient(to top right, #bae6fd, #e0f2fe, #ccfbf1);
            background-attachment: fixed;
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 1180px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #0d9488 0%, #06b6d4 100%);
            color: #ffffff;
            padding: 40px 35px;
            border-radius: 20px;
            margin-bottom: 40px;
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
        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03), 0 10px 30px rgba(15, 23, 42, 0.04);
        }
        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #f1f5f9;
            background: linear-gradient(90deg, #f0fdfa 0%, #ffffff 100%);
            margin: -28px -28px 24px -28px;
            padding: 18px 28px;
            border-radius: 16px 16px 0 0;
        }
        .card-title {
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 900;
            margin: 0;
            color: #0f172a;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-badge {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 10px;
            font-weight: 800;
            padding: 5px 11px;
            border-radius: 8px;
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
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid #e2e8f0;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
        }
        th {
            background: #0d9488;
            color: #ffffff;
            font-weight: 800;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: none;
        }
        tr:hover {
            background-color: #f0fdfa;
        }
        tbody tr:nth-child(even) {
            background-color: #f8fafc;
        }
        .mono {
            font-family: Consolas, Monaco, "Andale Mono", "Ubuntu Mono", monospace;
        }
        .tag {
            display: inline-block;
            font-size: 11px;
            font-weight: 800;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            color: #334155;
            padding: 4px 10px;
            border-radius: 8px;
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

export function buildScanReportBody(data) {
  const r = data.results || {}
  const geo = r.geo_ip || {}
  const ports = r.port_scan || {}
  const dns = r.dns_records || {}
  const ssl = r.ssl_certificate || {}
  const tech = r.web_technologies || {}
  const headers = r.http_headers || {}
  const subdomains = r.subdomains || {}

  const isOk = isModuleOk
  const getStatusLabel = moduleStatusBadge

  return `
        <!-- Header -->
        <div class="header">
            <div class="subtitle">Host Diagnostics Report</div>
            <h1>🧭 ${data.target}</h1>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="label">Resolved IP</span>
                    <span class="value">${data.resolved_ip || 'N/A'}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scan Mode</span>
                    <span class="value">${(data.scan_mode || 'FAST').toUpperCase()}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scan Duration</span>
                    <span class="value">${data.scan_duration_seconds ? data.scan_duration_seconds + 's' : 'N/A'}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scanned At</span>
                    <span class="value">${new Date(data.scanned_at || Date.now()).toLocaleString()}</span>
                </div>
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
            ${isOk(r.port_scan) ? `
            <div class="meta-summary-bar">
                <span>Scanned: <strong>${ports.scanned_port_count || 0}</strong></span> |
                <span>Open: <strong style="color: #15803d;">${ports.open_port_count || 0}</strong></span> |
                <span>Closed: <strong>${ports.closed_port_count || 0}</strong></span> |
                <span>Filtered: <strong style="color: #d97706;">${ports.filtered_port_count || 0}</strong></span>
            </div>
            ${ports.open_ports && ports.open_ports.length > 0 ? `
            <table style="margin-top: 15px;">
                <thead>
                    <tr>
                        <th style="width: 15%;">Port</th>
                        <th style="width: 15%;">Protocol</th>
                        <th style="width: 25%;">Service</th>
                        <th style="width: 20%;">Version</th>
                        <th style="width: 25%;">Service Header</th>
                    </tr>
                </thead>
                <tbody>
                    ${ports.open_ports.map(p => `
                    <tr>
                        <td class="mono" style="font-weight: bold; color: #ea580c;">${p.port}</td>
                        <td><span class="tag">TCP</span></td>
                        <td><strong>${p.service || 'unknown'}</strong></td>
                        <td>${p.version ? `<span class="tag tag-teal">${p.version}</span>` : '<span style="color: #94a3b8;">—</span>'}</td>
                        <td class="mono" style="font-size: 11px; word-break: break-all;">${p.banner || '—'}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            ` : `<p class="fallback-text" style="margin-top: 15px;">No active listening services detected on the scanned ports.</p>`}
            ` : `<p class="fallback-text">No port scanning information was successfully collected.</p>`}
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
            ${data.is_domain ? (
              isOk(r.subdomains) ? `
              <div style="font-size: 10px; font-style: italic; color: #64748b; margin-bottom: 12px;">
                  * Discovered ${Object.values(subdomains.sources || {}).reduce((acc, curr) => acc + (curr.count || 0), 0)} raw subdomain matches in total across all sources. These have been merged and deduplicated into ${subdomains.subdomains?.length || 0} unique subdomains below.
              </div>
              ${subdomains.subdomains && subdomains.subdomains.length > 0 ? `
              <table style="border: 1px solid #e2e8f0; border-radius: 8px;">
                  <thead>
                      <tr>
                          <th>Subdomain</th>
                          <th>Resolved IP</th>
                          <th>Source Provider</th>
                      </tr>
                  </thead>
                  <tbody>
                      ${subdomains.subdomains.map(s => `
                      <tr>
                          <td class="mono" style="font-weight: bold; color: #581c87; word-break: break-all;">${s.subdomain}</td>
                          <td class="mono">${s.ip ? `<span style="color: #15803d; font-weight: bold;">${s.ip}</span>` : '<span style="color: #94a3b8;">—</span>'}</td>
                          <td style="font-size: 10px; text-transform: uppercase; font-weight: bold; color: #6b21a8;">${s.source || '—'}</td>
                      </tr>
                      `).join('')}
                  </tbody>
              </table>
              ` : `<p class="fallback-text">No subdomains were discovered.</p>`}
              ` : `<p class="fallback-text">No subdomain enumeration was executed.</p>`
            ) : `<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>`}
        </div>

        <!-- Directory Enumeration -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📂 Directory Enumeration</h3>
                ${getStatusLabel(r.directory_enum)}
            </div>
            ${isOk(r.directory_enum) ? `
            <div class="meta-summary-bar" style="margin-bottom: 15px;">
                <span>Paths Checked: <strong>${r.directory_enum.paths_checked || 0}</strong></span> |
                <span>Found: <strong style="color: #15803d;">${r.directory_enum.found?.length || 0}</strong></span>
            </div>
            ${r.directory_enum.found && r.directory_enum.found.length > 0 ? `
            <table style="border: 1px solid #e2e8f0; border-radius: 8px;">
                <thead>
                    <tr>
                        <th style="width: 15%;">Status</th>
                        <th style="width: 55%;">Path & URL</th>
                        <th style="width: 30%;">Content Type</th>
                    </tr>
                </thead>
                <tbody>
                    ${r.directory_enum.found.map(p => `
                    <tr>
                        <td style="font-weight: bold; color: ${p.status === 200 ? '#16a34a' : (p.status === 403 ? '#dc2626' : (p.status >= 300 && p.status < 400 ? '#2563eb' : '#64748b'))};">${p.status}</td>
                        <td class="mono" style="word-break: break-all; font-weight: bold; color: #0f172a;">
                            ${p.path}
                            ${p.url ? `<br><a href="${p.url}" target="_blank" style="font-size: 10px; color: #0284c7; font-weight: normal; text-decoration: none;">${p.url}</a>` : ''}
                        </td>
                        <td style="font-size: 11px; text-transform: uppercase; color: #475569;">${p.content_type || '—'}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            ` : `<p class="fallback-text">No open directories/files were found.</p>`}
            ` : `<p class="fallback-text">Directory enumeration was not executed.</p>`}
        </div>

        <!-- IP Reputation & Threat Intelligence -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">⚠️ IP Reputation & Threat Intelligence</h3>
                <div>
                    ${getStatusLabel(r.reputation)} ${getStatusLabel(r.virustotal)}
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <!-- AbuseIPDB -->
                ${isOk(r.reputation) ? `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px;">
                    <h4 style="font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; font-weight: bold;">AbuseIPDB Reputation</h4>
                    <table class="kv-table" style="font-size: 12px;">
                        <tr><th style="width: 50%;">IP Address</th><td class="mono" style="font-weight: bold;">${r.reputation.ip || '—'}</td></tr>
                        <tr><th>Threat Level</th><td><span style="font-weight: bold; color: ${r.reputation.threat_level === 'critical' ? '#b91c1c' : r.reputation.threat_level === 'high' ? '#dc2626' : r.reputation.threat_level === 'medium' ? '#f59e0b' : '#10b981'};">${(r.reputation.threat_level || '—').toUpperCase()}</span></td></tr>
                        <tr><th>Abuse Confidence</th><td><strong style="color: ${r.reputation.abuse_confidence_score > 75 ? '#b91c1c' : r.reputation.abuse_confidence_score > 50 ? '#f59e0b' : '#10b981'};">${r.reputation.abuse_confidence_score || 0}%</strong></td></tr>
                        <tr><th>Total Reports</th><td><strong>${r.reputation.total_reports || 0}</strong></td></tr>
                        <tr><th>Country</th><td>${r.reputation.country_name ? `${r.reputation.country_name} (${r.reputation.country_code})` : '—'}</td></tr>
                        <tr><th>ISP/Organization</th><td>${r.reputation.isp || '—'}</td></tr>
                        <tr><th>Tor Network</th><td>${r.reputation.is_tor ? '<span style="color: #b91c1c; font-weight: bold;">YES (Exit Node)</span>' : 'No'}</td></tr>
                        <tr><th>VPN/Proxy</th><td>${r.reputation.is_proxy ? '<span style="color: #f59e0b; font-weight: bold;">YES</span>' : 'No'}</td></tr>
                        <tr><th>Whitelisted</th><td>${r.reputation.is_whitelisted ? '<span style="color: #10b981; font-weight: bold;">YES</span>' : 'No'}</td></tr>
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
            ${data.is_domain ? (
              isOk(r.email_gather) ? `
              <div class="meta-summary-bar" style="margin-bottom: 15px;">
                  <span>Total Discovered: <strong style="color: #6d28d9;">${r.email_gather.total_found || r.email_gather.emails?.length || 0}</strong></span> |
                  <span>Employee Accounts: <strong>${r.email_gather.employee_accounts_count || (r.email_gather.emails || []).filter(e => e.account_type === 'employee').length}</strong></span> |
                  <span>Role Accounts: <strong>${r.email_gather.role_accounts_count || (r.email_gather.emails || []).filter(e => e.account_type === 'role').length}</strong></span> |
                  <span>Exposed/Leaked: <strong style="color: #b91c1c;">${r.email_gather.leaked_accounts_count || (r.email_gather.emails || []).filter(e => e.is_leaked).length}</strong></span>
              </div>
              ${r.email_gather.emails && r.email_gather.emails.length > 0 ? `
              <table style="border: 1px solid #e2e8f0; border-radius: 8px;">
                  <thead>
                      <tr>
                          <th style="width: 50%;">Email Address</th>
                          <th style="width: 20%;">Type</th>
                          <th style="width: 30%;">Sources</th>
                      </tr>
                  </thead>
                  <tbody>
                      ${r.email_gather.emails.map(e => `
                      <tr>
                          <td class="mono" style="font-weight: bold; color: #1e293b;">${e.email}</td>
                          <td>
                              <span class="tag ${e.account_type === 'employee' ? 'tag-teal' : 'tag-slate'}">${e.account_type}</span>
                              ${e.is_leaked ? '<span class="tag" style="background-color:#ffe4e6; color:#9f1239;">Leaked</span>' : ''}
                          </td>
                          <td style="font-size: 10px;">${(e.sources || []).join(', ')}</td>
                      </tr>
                      `).join('')}
                  </tbody>
              </table>
              ` : `<p class="fallback-text">No email addresses discovered for this domain.</p>`}
              ` : `<p class="fallback-text">Email harvesting was not executed.</p>`
            ) : `<p class="fallback-text" style="color: #64748b; font-style: italic;">Domain-specific scan skipped: Target is a direct IP address.</p>`}
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

  const isOk = isModuleOk
  const getStatusLabel = moduleStatusBadge

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
      pane: 'tech', icon: '🛠️', label: 'Web Technologies',
      value: techCount > 0 ? `${techCount} identified` : 'None identified',
      tone: 'neutral',
    },
    data.is_domain && {
      pane: 'subdomains', icon: '📁', label: 'Subdomains',
      value: subdomainsCount > 0 ? `${subdomainsCount} discovered` : 'None found',
      tone: 'neutral',
    },
    {
      pane: 'cloud', icon: '☁️', label: 'Cloud Provider',
      value: cloudDetected ? r.cloud_provider.provider : 'Self-hosted / non-cloud',
      tone: 'neutral',
    },
    {
      pane: 'cms', icon: '🧩', label: 'CMS Platform',
      value: cmsDetected ? r.cms_fingerprint.cms_name : 'No known CMS',
      tone: 'neutral',
    },
  ].filter(Boolean)

  const navItems = [
    { pane: 'dns', icon: '🌐', label: 'DNS Records', domainOnly: true, badge: dnsTypesCount > 0 ? String(dnsTypesCount) : null },
    { pane: 'whois', icon: '📄', label: 'WHOIS Registry', domainOnly: true },
    { pane: 'ssl', icon: '🔒', label: 'SSL Certificate', badge: sslDays != null ? `${sslDays}d` : null },
    { pane: 'geoip', icon: '📍', label: 'GeoIP Location' },
    { pane: 'tech', icon: '🛠️', label: 'Web Technologies', badge: techCount > 0 ? String(techCount) : null },
    { pane: 'headers', icon: '🛡️', label: 'Security Headers', badge: headersCount > 0 ? String(headersCount) : null },
    { pane: 'waf', icon: '🛡️', label: 'WAF Detection', badge: wafDetected ? '!' : null },
    { pane: 'subdomains', icon: '📁', label: 'Subdomains', domainOnly: true, badge: subdomainsCount > 0 ? String(subdomainsCount) : null },
    { pane: 'cloud', icon: '☁️', label: 'Cloud Provider' },
    { pane: 'cms', icon: '🧩', label: 'CMS Detection' },
  ].filter(item => !item.domainOnly || data.is_domain)

  return `
        <!-- Header -->
        <div class="header">
            <div class="subtitle">Host Diagnostics Report</div>
            <h1>🧭 ${data.target}</h1>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="label">Resolved IP</span>
                    <span class="value">${data.resolved_ip || 'N/A'}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scan Mode</span>
                    <span class="value">${data.scan_mode === 'fast' ? 'STANDARD SCAN' : 'DEEP SCAN'}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scan Duration</span>
                    <span class="value">${data.scan_duration_seconds ? data.scan_duration_seconds + 's' : 'N/A'}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Scanned At</span>
                    <span class="value">${new Date(data.scanned_at || Date.now()).toLocaleString()}</span>
                </div>
            </div>
        </div>

        <div class="report-two-pane">
            <!-- Sidebar -->
            <div class="report-sidebar">
                <div class="report-sidebar-title">Modules</div>
                <button class="sidebar-btn active" data-pane="overview" onclick="showReportPane('overview', this)">📊 Overview</button>
                ${navItems.map(item => `
                <button class="sidebar-btn" data-pane="${item.pane}" onclick="showReportPane('${item.pane}', this)">
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

                <!-- Subdomains -->
                ${data.is_domain ? `
                <div id="pane-subdomains" class="content-pane" hidden>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">📁 Subdomains Index</h3>
                        ${getStatusLabel(r.subdomains)}
                    </div>
                    ${isOk(r.subdomains) ? `
                    <div style="font-size: 10px; font-style: italic; color: #64748b; margin-bottom: 12px;">
                        * Discovered ${Object.values(subdomains.sources || {}).reduce((acc, curr) => acc + (curr.count || 0), 0)} raw subdomain matches in total across all sources. These have been merged and deduplicated into ${subdomains.subdomains?.length || 0} unique subdomains below.
                    </div>
                    ${subdomains.subdomains && subdomains.subdomains.length > 0 ? `
                    <table style="border: 1px solid #e2e8f0; border-radius: 8px;">
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>Resolved IP</th>
                                <th>Source Provider</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${subdomains.subdomains.map(s => `
                            <tr>
                                <td class="mono" style="font-weight: bold; color: #581c87; word-break: break-all;">${s.subdomain}</td>
                                <td class="mono">${s.ip ? `<span style="color: #15803d; font-weight: bold;">${s.ip}</span>` : '<span style="color: #94a3b8;">—</span>'}</td>
                                <td style="font-size: 10px; text-transform: uppercase; font-weight: bold; color: #6b21a8;">${s.source || '—'}</td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    ` : `<p class="fallback-text">No subdomains were discovered.</p>`}
                    ` : `<p class="fallback-text">No subdomain enumeration was executed.</p>`}
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
        const statusClass = item.status === 'completed' ? 'ok' : item.status === 'failed' || item.status === 'timeout' ? 'error' : 'skipped'

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