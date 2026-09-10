import { useState } from 'react'
import {
  ArrowLeft,
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
  Loader2,
  Cloud,
  ShieldAlert,
  Fingerprint,
  Mail,
  Download,
  Radar,
  Wifi
} from 'lucide-react'

import {
  GeoSection,
  DnsSection,
  WhoisSection,
  SslSection,
  PortsSection,
  TechSection,
  HeadersSection,
  HEADER_IDEAL_CONFIGS,
  SubdomainsSection,
  DirectoriesSection,
  AbuseIpdbCard,
  VirusTotalCard,
  ReverseDnsSection,
  CloudProviderSection,
  WafDetectionSection,
  CmsFingerprintSection,
  EmailGatherSection,
  ShodanSection,
  HttpAvailabilitySection
} from './Results'

import {
  MAX_BATCH_TARGETS,
  classifyPrivateIp,
  classifyMalformedIp,
  looksLikeIp,
  looksLikeIpv6,
  expandIpRange,
  parseTargetList,
  countRawExpandedTargets,
  RANGE_SHORT_RE,
  RANGE_FULL_RE
} from '../utils/batchTargets'

const MODULE_DETAILS = {
  dns_records: {
    icon: Globe,
    title: 'DNS Records (Domain Name System)',
    desc: 'Perform active Domain Name System (DNS) queries against standard zone records of the target domain. This resolves the human-readable hostname to server-level IP addresses and retrieves routing mappings.',
    details: [
      'A Record (Address): Maps domain to IPv4 (Internet Protocol Version 4) address',
      'AAAA Record (Quad-A): Maps domain to IPv6 (Internet Protocol Version 6) address',
      'MX Record (Mail Exchanger): Identifies mail servers responsible for routing incoming email',
      'NS Record (Name Server): Lists authoritative name servers responsible for the domain zone',
      'TXT Record (Text): Contains raw text metadata used for domain verification and configuration tags',
      'CNAME Record (Canonical Name): Creates aliases pointing one hostname to another canonical hostname',
      'SOA Record (Start of Authority): Provides core zone metadata including the primary name server and administrator email',
      'CAA Record (Certification Authority Authorization): Specifies which Certificate Authorities (CAs) are allowed to issue SSL/TLS certificates',
      'SPF Record (Sender Policy Framework): Lists authorized mail servers allowed to send messages from the domain',
      'DMARC Record (Domain-based Message Authentication): Defines enforcement policies for SPF/DKIM authentication failures',
      'DKIM Record (DomainKeys Identified Mail): Holds cryptographic public keys to authenticate email sender integrity'
    ],
    howItChecked: 'This check uses Python\'s `dnspython` package to perform concurrent DNS queries directly against the target\'s nameservers. If default system resolvers fail or time out, it automatically falls back to querying public DNS servers (Google 8.8.8.8 and Cloudflare 1.1.1.1) to ensure high resolution reliability.',
    color: 'text-blue-600 bg-blue-50 border-blue-100',
    btnStyle: 'bg-blue-600 hover:bg-blue-700 focus:ring-blue-500 glow-blue shadow-blue-200/50'
  },
  whois: {
    icon: FileText,
    title: 'WHOIS Registry Query',
    desc: 'Query registrar databases using RDAP (Registration Data Access Protocol) and traditional WHOIS servers to discover domain ownership, contact details, registration dates, and delegated name servers.',
    details: [
      'Domain Registrar: The accredited organization managing the domain registration',
      'Registration Dates: Tracking creation, last update, and expiration milestones',
      'Registrant Contact: Information about the domain owner organization, country, and admin point-of-contacts',
      'Authoritative Name Servers: Identifying delegated servers directing traffic to DNS resolvers'
    ],
    howItChecked: 'This check queries Registration Data Access Protocol (RDAP) databases and standard WHOIS port 43 servers using the Python `python-whois` library. It parses ownership records, registrar credentials, active nameservers, and registration/expiry milestones.',
    color: 'text-slate-600 bg-slate-100 border-slate-200',
    btnStyle: 'bg-slate-700 hover:bg-slate-800 focus:ring-slate-500 glow-slate shadow-slate-200/50'
  },
  ssl_certificate: {
    icon: Lock,
    title: 'SSL/TLS Certificate Check',
    desc: 'Inspect the SSL (Secure Sockets Layer) and TLS (Transport Layer Security) cryptographic certificate chain to verify connection security, validation authority, expiration dates, and cipher configurations.',
    details: [
      'Common Name (CN): The primary host address bound to the security certificate',
      'Subject Alternative Names (SANs): Secondary hostname aliases secured under the same certificate',
      'Certificate Issuer: The trusted Certificate Authority (CA) validating and signing the certificate',
      'Validity Range: Expiration dates and days remaining to prevent protocol disruption',
      'Supported TLS Versions: Verification of active protocols (TLS 1.2, TLS 1.3) and legacy deprecated protocols (TLS 1.0, TLS 1.1)',
      'Cryptographic Cipher Suites: Scanning supported algorithms for symmetric encryption, key exchanges (e.g. ECDHE), and message authentication'
    ],
    howItChecked: 'This check initiates direct TLS connections using Python\'s built-in standard `ssl` and `socket` modules. It pulls the certificate payload, subject alternative aliases (SANs), verifies validity durations, and runs connection sweeps to audit active cipher suites and supported TLS versions.',
    color: 'text-teal-600 bg-teal-50 border-teal-100',
    btnStyle: 'bg-teal-600 hover:bg-teal-700 focus:ring-teal-500 glow-sage shadow-teal-200/50'
  },
  geo_ip: {
    icon: MapPin,
    title: 'GeoIP Location & ISP Data',
    desc: 'Query IP (Internet Protocol) database registries to resolve the server geographical coordinates, hosting datacenter profiles, ISP (Internet Service Provider) information, and ASN (Autonomous System Number) identifiers.',
    details: [
      'Geographic Placement: Resolving host country, region state, city, and coordinates',
      'ISP (Internet Service Provider): The network operator supplying internet connectivity to the server',
      'ASN (Autonomous System Number): The unique identifier for the network routing block (e.g. AS15169)',
      'Network Classification: Checking if the IP belongs to a proxy/VPN, residential line, or server hosting datacenter'
    ],
    howItChecked: 'This check resolves hostnames into active IP addresses via Python\'s standard `socket` module. It then queries the free `ip-api.com` database via `aiohttp` to map the IP address to geographic coordinates, network operators, and autonomous systems.',
    color: 'text-red-655 text-red-600 bg-red-50 border-red-100',
    btnStyle: 'bg-red-600 hover:bg-red-700 focus:ring-red-500 glow-red shadow-red-200/50'
  },
  http_headers: {
    icon: FileCode,
    title: 'HTTP Response Headers',
    desc: 'Send Hypertext Transfer Protocol (HTTP) queries to the target web server to fetch response headers, inspect cookie parameters, and check for the presence of recommended security headers.',
    details: [
      'Server Banner & Engine: Extracting web server signatures (e.g. Apache, Nginx, IIS)',
      'Security Headers Audit: Inspecting critical protective headers like HSTS (HTTP Strict Transport Security), CSP (Content Security Policy), X-Frame-Options, and Referrer-Policy',
      'Session Cookie Security: Auditing cookie flags such as Secure, HttpOnly, and SameSite to prevent scripting leaks',
      'HTTP Redirect Tracer: Mapping connection hops, HTTP status codes (e.g. 301, 302), and final destinations'
    ],
    howItChecked: 'This check sends asynchronous HTTP GET queries using the Python `aiohttp` client library. It extracts raw headers, parses cookie security tags (HttpOnly, Secure, SameSite), and tracks redirectional hops (301/302 codes) to their final destination targets.',
    color: 'text-cyan-600 bg-cyan-50 border-cyan-100',
    btnStyle: 'bg-cyan-600 hover:bg-cyan-700 focus:ring-cyan-500 glow-cyan shadow-cyan-200/50'
  },
  web_technologies: {
    icon: Layers,
    title: 'Web Technologies & Frameworks',
    desc: 'Examine HTTP responses, page scripts, and a live-rendered browser pass to identify the underlying operating systems, programming languages, web framework stacks, content delivery networks, and third-party widgets — including exact version numbers where the technology exposes one.',
    details: [
      'Web Server & Reverse Proxy: Detecting edge servers (e.g. Nginx, Cloudflare)',
      'Programming Languages & Frameworks: Identifying backend engines (e.g. PHP, ASP.NET) and frontend frameworks (e.g. React, Vue)',
      'CMS (Content Management System): Recognizing content platforms (e.g. WordPress, Joomla)',
      'CDN (Content Delivery Network): Pinpointing edge caching systems routing web assets',
      'Analytics & Utilities: Identifying tracking tools, font libraries, and scripts',
      'Version Fingerprinting: Extracting exact version numbers (e.g. jQuery 3.6.0, Next.js 14.2) from HTTP headers and live JavaScript runtime properties'
    ],
    howItChecked: 'This check pulls the home page over HTTP using the `aiohttp` client library, then runs pattern matching against a large Wappalyzer-style signature catalog covering headers, cookies, meta tags, script sources, and page content to detect frameworks, libraries, CDNs, and analytics trackers. A real headless browser also renders the page once to read live JavaScript runtime properties (e.g. `React.version`, `jQuery.fn.jquery`) — many modern frameworks only expose an exact version number this way, since it never appears in raw HTTP responses.',
    color: 'text-amber-600 bg-amber-50 border-amber-100',
    btnStyle: 'bg-amber-600 hover:bg-amber-700 focus:ring-amber-500 glow-amber shadow-amber-200/50'
  },
  abuseipdb: {
    icon: AlertTriangle,
    title: 'AbuseIPDB Threat Reputation',
    desc: 'Query the AbuseIPDB API (Application Programming Interface) database to check if the target IP address has been flagged for malicious activities like spamming, port scanning, brute-forcing, or DDoS (Distributed Denial of Service) attacks.',
    details: [
      'Abuse Confidence Score: Probability rating (0% to 100%) indicating how likely the IP is malicious',
      'Report Frequency: Tracking the count of unique reports submitted by system administrators',
      'Last Report Timestamp: Historical timeline logs of recent security incidents'
    ],
    howItChecked: 'This check queries the AbuseIPDB API database using asynchronous request handles via `aiohttp`. It reports threat history data, malicious confidence ratings, and node report histories for resolved IPs.',
    color: 'text-orange-600 bg-orange-50 border-orange-100',
    btnStyle: 'bg-orange-600 hover:bg-orange-700 focus:ring-orange-500 glow-orange shadow-orange-200/50'
  },
  virustotal: {
    icon: Bug,
    title: 'VirusTotal Threat Intel',
    desc: 'Query the VirusTotal threat repository to inspect malicious flags, domain reputational feedback, and malware associations aggregated from 70+ endpoint security vendors.',
    details: [
      'Detections Count: Number of security engines flagging the domain or IP as malicious or suspicious',
      'Reputation Analytics: Analyzing classification outputs (e.g. Harmless, Malicious, Undetected)',
      'Registry Categories: Mapping threats to categories like Phishing, Malware distribution, or Command and Control (C2)'
    ],
    howItChecked: 'This check queries the VirusTotal v3 REST API threat repository asynchronously using the `aiohttp` library. It analyzes flags from over 70 third-party security vendors to classify if the domain or IP is flagged as malicious, clean, or suspicious.',
    color: 'text-rose-600 bg-rose-50 border-rose-100',
    btnStyle: 'bg-rose-600 hover:bg-rose-700 focus:ring-rose-500 glow-red shadow-rose-200/50'
  },
  port_scan: {
    icon: Server,
    title: 'TCP Ports & Service Scanner',
    desc: 'Probe active TCP (Transmission Control Protocol) ports on the target host to determine socket statuses, map standard network services, and read greeting banners.',
    details: [
      'Port State Audit: Classifying ports as Open (accepts connection), Closed (rejects connection), or Filtered (blocked by firewall)',
      'Protocol Services Mapping: Identifying active standard protocol services (e.g. Port 80 for HTTP, 443 for HTTPS, 22 for SSH)',
      'Service Banners & Greetings: Connecting to open ports to capture raw banners to identify software names and exact versions'
    ],
    howItChecked: 'This check executes active socket scans concurrently against the target IP using Python\'s built-in `socket` module wrapped inside a ThreadPoolExecutor. It verifies connection states (Open, Closed, Filtered) and grabs greetings banner headers to identify software versions.',
    color: 'text-indigo-600 bg-indigo-50 border-indigo-100',
    btnStyle: 'bg-indigo-600 hover:bg-indigo-700 focus:ring-indigo-500 glow-indigo shadow-indigo-200/50'
  },
  subdomains: {
    icon: GitBranch,
    title: 'Subdomain Indexing (OSINT)',
    desc: 'Harvest subdomains using certificate transparency (CT) logs and passive search databases to map the target domain\'s public-facing attack surface.',
    details: [
      'Multi-Source Passive OSINT: Queries 15+ external engines including crt.sh, HackerTarget, AlienVault OTX, URLScan, RapidDNS, CertSpotter, Wayback Machine, Anubis, Subdomain Center, ThreatMiner, VirusTotal, Robtex, BeVigil, Netlas, and Search Engine dorks',
      'Local CLI Tool Integration: Leverages installed tools like subfinder, findomain, amass, assetfinder, and theHarvester to perform targeted scanning',
      'Reverse-IP Infrastructure Mapping: Queries Shodan InternetDB on resolved IPs to find hidden domains sharing the same servers',
      'Altdns Permutations & Mutations: Generates subdomains dynamically using microservice naming patterns and env prefixes (e.g., dev, staging, prod)',
      'Active Wordlist Bruteforcing: Runs concurrent DNS queries against common prefixes and microservices to detect unlisted hosts',
      'Asynchronous DNS Resolution: Concurrently validates all discovered subdomains to check for live IPv4 (A) and IPv6 (AAAA) records using a high-performance system resolver thread pool'
    ],
    howItChecked: 'This check aggregates subdomains from 15+ passive OSINT sources, 5 local CLI tools, and a wordlist bruteforcer. It then resolves each host via a 500-worker thread pool executing `socket.getaddrinfo` to fetch IPv4/IPv6 records. Finally, it queries Shodan InternetDB for reverse-IP mappings and runs a recursive/permutation discovery engine to uncover nested subdomains.',
    color: 'text-purple-600 bg-purple-50 border-purple-200',
    btnStyle: 'bg-purple-600 hover:bg-purple-700 focus:ring-purple-500 glow-purple shadow-purple-200/50'
  },
  directories: {
    icon: FolderOpen,
    title: 'Directory & Path Enumeration',
    desc: 'Run concurrent directory fuzzing checks against common paths to identify exposed administration panels, backup files, configuration leaks, and directories.',
    details: [
      'HTTP Status Code Resolution: Resolving paths to identify valid endpoints (e.g. 200 OK, 403 Forbidden, 401 Unauthorized)',
      'Exposed Configuration Files: Searching for configuration files (e.g. `/.env`, `/.git`, `/config.json`)',
      'Content-Length & Mimetype Audit: Reviewing response sizes and MIME types to isolate genuine files from wildcard fallback pages'
    ],
    howItChecked: 'This check executes directory fuzzer checks by sending asynchronous HTTP requests using the `aiohttp` package. It tests the target host against a wordlist of 200+ default configuration paths and administrative directories, filtering wildcards dynamically.',
    color: 'text-teal-600 bg-teal-50 border-teal-100',
    btnStyle: 'bg-emerald-600 hover:bg-emerald-700 focus:ring-emerald-500 glow-sage shadow-emerald-200/50'
  },
  reverse_dns: {
    icon: RefreshCw,
    title: 'Reverse DNS PTR Lookup',
    desc: 'Perform a reverse Domain Name System (DNS) query (PTR record lookup) to map the host IP address back to its registered hostname, checking for nameserver alignment.',
    details: [
      'PTR Record (Pointer): Mapping the IP address back to a canonical host name',
      'Resolver Comparison: Cross-checking local socket resolver results against nslookup tool output',
      'Forward-Reverse Matching: Verifying if the resolved hostname maps back to the origin IP address'
    ],
    howItChecked: 'This check performs comparative reverse lookups using Python\'s built-in `socket.gethostbyaddr` resolver. If resolution fails, it invokes the local CLI utility `nslookup` via a subprocess call to ensure reliable PTR record matching.',
    color: 'text-violet-700 bg-violet-50 border-violet-200',
    btnStyle: 'bg-violet-600 hover:bg-violet-700 focus:ring-violet-500 glow-violet shadow-violet-200/50'
  },
  cloud_provider: {
    icon: Cloud,
    title: 'Cloud Infrastructure Provider',
    desc: 'Cross-reference the host IP address against CIDR (Classless Inter-Domain Routing) IP block registries to identify if the target is hosted on AWS, Azure, Google Cloud, Cloudflare, or other systems.',
    details: [
      'CIDR Range Matching: Checking IP blocks published by cloud networks (AWS, GCP, Azure, Cloudflare, DigitalOcean)',
      'ASN Organization Audit: Extracting Autonomous System details to verify host organization properties',
      'Hosting Datacenter Identification: Classifying whether the server is residential, commercial, or a virtual private server (VPS)'
    ],
    howItChecked: 'This check maps resolved IPs against official public subnet ranges using Python\'s built-in standard `ipaddress` library. It matches AWS, Google Cloud, Microsoft Azure, Cloudflare, Oracle, and other cloud network CIDR IP blocks.',
    color: 'text-sky-600 bg-sky-50 border-sky-100',
    btnStyle: 'bg-sky-600 hover:bg-sky-700 focus:ring-sky-500 shadow-sky-200/50'
  },
  waf_detect: {
    icon: ShieldAlert,
    title: 'WAF Firewall Detection',
    desc: 'Identify Web Application Firewalls (WAFs) protecting the target server by sending simulated attack queries (such as SQL Injection or Cross-Site Scripting payloads) and matching block responses against known WAF patterns.',
    details: [
      'Signature Matching: Auditing response headers and body content against 20+ firewall vendors (Cloudflare, AWS WAF, Akamai, Sucuri)',
      'Block Codes Audit: Identifying firewall actions on blocked probes (e.g. HTTP 403 Forbidden, 406 Not Acceptable, 429 Too Many Requests)',
      'Confidence Analysis: Evaluating responses from safe vs. attack payloads to confirm WAF presence'
    ],
    howItChecked: 'This check sends safe probes and crafted payload queries (SQLi and XSS payloads) using the `aiohttp` library. It matches block responses and headers against a signature set of 20+ firewall vendors (Cloudflare, AWS WAF, Akamai).',
    color: 'text-red-600 bg-red-50 border-red-100',
    btnStyle: 'bg-red-600 hover:bg-red-700 focus:ring-red-500 shadow-red-200/50'
  },
  cms_fingerprint: {
    icon: Fingerprint,
    title: 'CMS Platform Identification',
    desc: 'Determine the Content Management System (CMS) or framework powering the website by analyzing generator meta tags, style folders, login paths, and script file footprints.',
    details: [
      'CMS Signature Matching: Detecting WordPress, Joomla, Drupal, Magento, Shopify, or Ghost',
      'Version Extraction: Parsing meta generator tags and scripts to identify specific software versions',
      'Framework Detections: Identifying modern frameworks like Next.js, Gatsby, Nuxt.js, or Hugo',
      'Path Probing: Checking default administrative endpoints (e.g. `/wp-admin`, `/administrator`)'
    ],
    howItChecked: 'This check probes CMS-specific folder endpoints (wp-login, /administrator) and reads HTML meta generator tags via the `aiohttp` client. It uses regular expression matchers to identify WordPress, Joomla, Shopify, and Magento platform versions.',
    color: 'text-fuchsia-600 bg-fuchsia-50 border-fuchsia-100',
    btnStyle: 'bg-fuchsia-600 hover:bg-fuchsia-700 focus:ring-fuchsia-500 shadow-fuchsia-200/50'
  },
  http_availability: {
    icon: Wifi,
    title: 'HTTP/HTTPS Accessibility',
    desc: 'Independently tests whether a target is reachable on port 80 (HTTP) and port 443 (HTTPS) — status code, response time, and HTTP version for each, plus whether HTTP is properly forced to redirect to HTTPS.',
    details: [
      'Port 80 (HTTP) Check: Raw status code and response time, without following redirects — so a misconfigured or missing HTTPS redirect is visible, not silently hidden',
      'Port 443 (HTTPS) Check: Status code, response time, and real HTTP/2 support detected via a direct TLS ALPN probe — the same mechanism a browser uses to choose HTTP/2 vs HTTP/1.1',
      'Forced-HTTPS Verification: Confirms whether HTTP actually redirects to HTTPS (and shows the redirect target), rather than assuming it does',
      'Independent Failure Classification: Each port is diagnosed separately — connection refused, filtered/no response, or TLS handshake failure — so a broken HTTPS setup doesn\'t get hidden behind a working HTTP response, or vice versa'
    ],
    howItChecked: 'Port 80 and 443 are probed concurrently and independently via `aiohttp` with redirects disabled, capturing the raw status code and any Location header. HTTP/2 capability on port 443 is verified separately via a raw TLS ALPN handshake using Python\'s `ssl` module, since neither this system\'s `curl` nor `aiohttp` itself can negotiate HTTP/2 on the wire.',
    color: 'text-lime-700 bg-lime-50 border-lime-200',
    btnStyle: 'bg-lime-600 hover:bg-lime-700 focus:ring-lime-500 shadow-lime-200/50'
  },
  email_gather: {
    icon: Mail,
    title: 'Email Harvesting',
    desc: 'Discover all email addresses publicly associated with the target domain — sourced from 15+ concurrent, API-key-free intelligence feeds.',
    details: [
      'PGP & Identity Directories: Queries Ubuntu, MIT, OpenPGP, and Keybase for employee public keys and verified identities',
      'Certificate Transparency & Web Archives: Extracts contact emails from SSL cert SAN fields (crt.sh) and Wayback Machine snapshots',
      'DNS & Mail Server Diagnostics: Parses DMARC (rua/ruf), SOA responsible-party fields, and probes SMTP (port 25) greeting banners',
      'Threat Intelligence & Web Indexes: Queries AlienVault OTX, ThreatMiner, URLScan.io, and CommonCrawl for indexed domain contacts',
      'Targeted Domain & Web Crawling: Deep scrapes leadership, staff, and contact pages across domain endpoints and DuckDuckGo snippets',
      'Code Repositories: Searches public GitHub repositories for exposed @domain email references'
    ],
    howItChecked: 'All 15+ sources are queried concurrently using async HTTP (aiohttp) and socket tasks. Results are deduplicated, filtered to only include @<target-domain> addresses, and tagged with a confidence level: HIGH = found in 2+ sources, MEDIUM = found in 1 source.',
    color: 'text-violet-600 bg-violet-50 border-violet-100',
    btnStyle: 'bg-violet-600 hover:bg-violet-700 focus:ring-violet-500 shadow-violet-200/50'
  },
  standalone_port_scanner: {
    icon: Server,
    title: 'Port Scanner Engine',
    desc: 'High-concurrency TCP port scanner supporting customizable port range choices (Top 100 ports, 1-1024 system ports, or full 1-65535 sweep). Probes socket states, grabs service banners, and detects firewall rules.',
    details: [
      'Top 100 Ports Option: Quick scan of the top 100 most important and critical TCP service ports',
      '1 - 1024 Ports Option: Comprehensive check across all standard well-known system ports (FTP, SSH, Web, Mail, RPC, Database)',
      '1 - 65535 Ports Option: Exhaustive full-range scan across all 65,535 TCP ports with high concurrency socket workers',
      'Banner & Service Detection: Connects to open ports to read service headers (HTTP, HTTPS, SSH, FTP, SMTP, MySQL, Postgres, Redis, etc.)',
      'Firewall & Packet Metrics: Categorizes ports into Open, Closed (RST), or Filtered (firewall packet drop)'
    ],
    howItChecked: 'This check launches multi-threaded socket probes using a high-concurrency Semaphore pool (300-400 concurrent workers) and adaptive timeouts (1.2s - 1.5s per probe) to ensure Nmap-grade accuracy without premature timeout drops.',
    color: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    btnStyle: 'bg-emerald-600 hover:bg-emerald-700 focus:ring-emerald-500 glow-sage shadow-emerald-200/50'
  },
  shodan_intel: {
    icon: Radar,
    title: 'Shodan Intel (InternetDB)',
    desc: "Cross-references the target IP against Shodan's own internet-wide scan data — open ports it has indexed, detected software versions, and known CVEs tied to those services. Free and keyless, useful for comparing against this tool's own live port probe.",
    details: [
      "Indexed Open Ports: Ports Shodan's own scanners have found open on this IP, from a separate historical vantage point than our live probe",
      "Detected Software (CPEs): Software and version strings Shodan has fingerprinted on the target's services",
      'Known Vulnerabilities: CVE identifiers Shodan associates with the detected software versions, linked out to NVD for details',
      "Associated Hostnames: Other hostnames Shodan has seen resolve to this same IP",
      'Threat/Infra Tags: Labels Shodan applies (e.g. cloud, self-signed, compromised) when applicable'
    ],
    howItChecked: "Queries Shodan's free InternetDB endpoint (internetdb.shodan.io) directly — no API key required. A private/reserved IP is rejected before the query runs, and a target Shodan simply hasn't indexed returns a clean \"no data\" result rather than an error.",
    color: 'text-indigo-700 bg-indigo-50 border-indigo-200',
    btnStyle: 'bg-indigo-600 hover:bg-indigo-700 focus:ring-indigo-500 glow-sage shadow-indigo-200/50'
  }
}

const BATCH_CAPABLE_MODULES = ['abuseipdb', 'virustotal', 'geo_ip', 'whois', 'ssl_certificate', 'dns_records', 'shodan_intel', 'http_availability', 'http_headers', 'web_technologies', 'reverse_dns']

const PUBLIC_IP_ONLY_MODULES = ['abuseipdb', 'virustotal', 'ssl_certificate', 'dns_records', 'shodan_intel', 'http_availability', 'http_headers', 'web_technologies', 'reverse_dns']

const DOMAIN_ONLY_MODULES = ['email_gather', 'whois']

const IP_ONLY_MODULES = ['reverse_dns']

export default function SingleModuleView({
  moduleKey,
  onBack,
  onStartScan,
  onStartModuleBatchScan,
  status,
  scanData,
  error,
  onReset,
  scanningTargets = []
}) {
  const meta = MODULE_DETAILS[moduleKey] || MODULE_DETAILS.dns_records
  const Icon = meta.icon
  const isBatchCapable = BATCH_CAPABLE_MODULES.includes(moduleKey)

  const [inputVal, setInputVal] = useState('')
  const [subQuery, setSubQuery] = useState('')
  const [subFilter, setSubFilter] = useState('all')
  const [dirFilter, setDirFilter] = useState('all')
  const [apiKey, setApiKey] = useState(() => {
    try {
      if (moduleKey === 'abuseipdb') return localStorage.getItem('recon_abuseipdb_key') || ''
      if (moduleKey === 'virustotal') return localStorage.getItem('recon_virustotal_key') || ''
      return ''
    } catch { return '' }
  })
  const [keyError, setKeyError] = useState('')
  const [portRange, setPortRange] = useState('top100')
  
  const handleApiKeyChange = (val) => {
    setApiKey(val)
    setKeyError('')
    try {
      if (moduleKey === 'abuseipdb') localStorage.setItem('recon_abuseipdb_key', val)
      if (moduleKey === 'virustotal') localStorage.setItem('recon_virustotal_key', val)
    } catch {}
  }

  const privateIpViolation = (() => {
    if (!PUBLIC_IP_ONLY_MODULES.includes(moduleKey) || !inputVal.trim()) return null
    let targets
    try {
      targets = isBatchCapable ? parseTargetList(inputVal) : [inputVal.trim()]
    } catch {
      return null
    }
    for (const t of targets) {
      const reason = classifyPrivateIp(t)
      if (reason) return { target: t, reason }
    }
    return null
  })()

  const domainOnlyViolation = (() => {
    if (!DOMAIN_ONLY_MODULES.includes(moduleKey) || !inputVal.trim()) return null
    let targets
    try {
      targets = isBatchCapable ? parseTargetList(inputVal) : [inputVal.trim()]
    } catch {
      return null
    }
    for (const t of targets) {
      if (looksLikeIp(t)) return { target: t }
    }
    return null
  })()

  const ipOnlyViolation = (() => {
    if (!IP_ONLY_MODULES.includes(moduleKey) || !inputVal.trim()) return null
    let targets
    try {
      targets = isBatchCapable ? parseTargetList(inputVal) : [inputVal.trim()]
    } catch {
      return null
    }
    for (const t of targets) {
      if (!looksLikeIp(t) && !looksLikeIpv6(t)) return { target: t }
    }
    return null
  })()

  const malformedIpViolation = (() => {
    if (!inputVal.trim()) return null
    let targets
    try {
      targets = isBatchCapable ? parseTargetList(inputVal) : [inputVal.trim()]
    } catch {
      return null
    }
    for (const t of targets) {
      const reason = classifyMalformedIp(t)
      if (reason) return { target: t, reason }
    }
    return null
  })()

  const handleScan = (e) => {
    e.preventDefault()
    if (!inputVal.trim() || status === 'scanning') return

    if (privateIpViolation) {
      setKeyError(`'${privateIpViolation.target}' is a ${privateIpViolation.reason}, not a public IP — this check only applies to public internet targets.`)
      return
    }

    if (domainOnlyViolation) {
      setKeyError(`'${domainOnlyViolation.target}' is an IP address — this check requires a domain name.`)
      return
    }

    if (malformedIpViolation) {
      setKeyError(`'${malformedIpViolation.target}' is ${malformedIpViolation.reason}.`)
      return
    }

    if (ipOnlyViolation) {
      setKeyError(`'${ipOnlyViolation.target}' is a domain — this check requires an IP address.`)
      return
    }

    if (moduleKey === 'abuseipdb' || moduleKey === 'virustotal') {
      if (!apiKey.trim()) {
        setKeyError('API Key is required to run this scan.')
        return
      }
      setKeyError('')
    }

    if (isBatchCapable) {
      let targets
      try {
        targets = parseTargetList(inputVal)
      } catch (rangeErr) {
        setKeyError(rangeErr.message)
        return
      }
      if (targets.length > MAX_BATCH_TARGETS) {
        setKeyError(`Too many targets (${targets.length}). Maximum is ${MAX_BATCH_TARGETS} per check.`)
        return
      }
      if (targets.length > 1) {
        onStartModuleBatchScan(targets, apiKey.trim(), moduleKey)
        return
      }
    }

    onStartScan(inputVal.trim(), apiKey.trim(), portRange)
  }

  const isBatch = Array.isArray(scanData?.results) && scanData?.batch_size !== undefined

  const generateHtmlReport = () => {
    const targets = isBatch ? scanData.results : [scanData];

    const getModuleHtml = (moduleKey, data) => {
      if (!data) return '<p class="empty">-</p>';
      
      if (moduleKey === 'dns_records') {
        const records = data.records_by_type || {};
        let html = '<div class="dns-container">';
        Object.entries(records).forEach(([type, val]) => {
          if (!val) return;
          const recs = val.records || [];
          html += `
            <div class="dns-type-block" style="margin-bottom: 25px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">
              <div class="dns-type-title" style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 1px; color: #475569; border-bottom: 1px solid #cbd5e1;">${type} RECORDS</div>
              <div style="padding: 15px;">
          `;
          if (val.status === 'error' || val.status === 'timeout') {
            html += `<div style="color: #b91c1c; font-size: 13px;">Error fetching records: ${val.error_message || 'Timeout'}</div>`;
          } else if (recs.length === 0) {
            html += `<p style="color: #94a3b8; font-style: italic; margin: 0; font-size: 13px;">No ${type} records configured.</p>`;
          } else {
            if (type === 'MX') {
              html += `
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                  <thead>
                    <tr style="background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;">
                      <th style="padding: 10px; font-weight: bold; width: 20%; color: #475569; text-align: left; border-bottom: 1px solid #cbd5e1;">PRIORITY</th>
                      <th style="padding: 10px; font-weight: bold; color: #475569; text-align: left; border-bottom: 1px solid #cbd5e1;">SERVER</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${recs.map(r => `
                      <tr style="border-bottom: 1px solid #cbd5e1;">
                        <td style="padding: 10px; font-weight: bold;">${r.priority}</td>
                        <td style="padding: 10px; font-family: monospace; font-weight: bold;">${r.server}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              `;
            } else if (type === 'SOA') {
              const s = recs[0] || {};
              html += `
                <table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px;">
                  <tr><td class="key" style="font-weight: bold; width: 30%; background-color: #f8fafc; padding: 10px; border-bottom: 1px solid #cbd5e1; color: #475569;">Primary Nameserver</td><td style="padding: 10px; border-bottom: 1px solid #cbd5e1; font-family: monospace;">${s.primary_ns || '-'}</td></tr>
                  <tr><td class="key" style="font-weight: bold; background-color: #f8fafc; padding: 10px; border-bottom: 1px solid #cbd5e1; color: #475569;">Responsible Email</td><td style="padding: 10px; border-bottom: 1px solid #cbd5e1; font-family: monospace;">${s.responsible_email || '-'}</td></tr>
                  <tr><td class="key" style="font-weight: bold; background-color: #f8fafc; padding: 10px; border-bottom: 1px solid #cbd5e1; color: #475569;">Serial Number</td><td style="padding: 10px; border-bottom: 1px solid #cbd5e1;">${s.serial || '-'}</td></tr>
                  <tr><td class="key" style="font-weight: bold; background-color: #f8fafc; padding: 10px; border-bottom: 1px solid #cbd5e1; color: #475569;">Refresh Interval</td><td style="padding: 10px; border-bottom: 1px solid #cbd5e1;">${s.refresh || '-'} seconds</td></tr>
                  <tr><td class="key" style="font-weight: bold; background-color: #f8fafc; padding: 10px; color: #475569;">Minimum TTL</td><td style="padding: 10px;">${s.minimum_ttl || '-'} seconds</td></tr>
                </table>
              `;
            } else if (type === 'DKIM') {
              html += recs.map(r => `
                <div style="margin-bottom: 15px; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
                  <div style="font-weight: bold; font-size: 11px; color: #475569; margin-bottom: 6px; text-transform: uppercase;">SELECTOR: ${r.selector}</div>
                  <div style="font-family: monospace; font-size: 12px; background-color: #f8fafc; padding: 8px; border-radius: 4px; word-break: break-all; color: #334155; line-height: 1.4;">${r.records ? r.records.join(', ') : ''}</div>
                </div>
              `).join('');
            } else {
              html += `<ul style="margin: 0; padding-left: 20px; font-family: monospace; font-size: 13px; color: #334155;">`;
              recs.forEach(r => {
                const valStr = typeof r === 'object' ? JSON.stringify(r) : String(r);
                html += `<li style="margin-bottom: 6px; word-break: break-all; font-weight: bold;">${valStr}</li>`;
              });
              html += `</ul>`;
            }
          }
          html += `</div></div>`;
        });
        html += '</div>';
        return html;
      }

      if (moduleKey === 'whois') {
        const formatDate = (d) => d ? new Date(d).toLocaleString() : '-';
        const fields = [
          ['Registrar', data.registrar],
          ['Registrar URL', data.registrar_url],
          ['Registrar IANA ID', data.registrar_iana_id],
          ['Registrar Abuse Email', data.registrar_abuse_email],
          ['Registrar Abuse Phone', data.registrar_abuse_phone],
          ['Creation Date', formatDate(data.creation_date)],
          ['Expiration Date', formatDate(data.expiration_date)],
          ['Updated Date', formatDate(data.updated_date)],
          ['Days Until Expiry', data.days_until_expiry != null ? `${data.days_until_expiry} days` : null],
          ['Expiry Status', data.expiry_status],
          ['Registrant Name', data.registrant_name],
          ['Registrant Org', data.registrant_org || data.org],
          ['Country', data.country],
          ['State', data.state],
          ['City', data.city],
          ['Address', data.address],
          ['Zipcode', data.zipcode],
          ['DNSSEC', data.dnssec]
        ];
        let html = '<table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">';
        fields.forEach(([k, v]) => {
          if (!v) return;
          html += `
            <tr style="border-bottom: 1px solid #cbd5e1;">
              <td style="font-weight: bold; width: 35%; background-color: #f8fafc; padding: 10px 15px; color: #475569;">${k}</td>
              <td style="padding: 10px 15px; word-break: break-all; font-weight: bold;">${v}</td>
            </tr>
          `;
        });
        html += '</table>';
        if (data.name_servers?.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; background-color: #f8fafc;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #475569; margin-bottom: 10px;">Nameservers</div>
              <ul style="margin: 0; padding-left: 20px; font-family: monospace; font-size: 13px; font-weight: bold;">
                ${data.name_servers.map(ns => `<li style="margin-bottom: 5px;">${ns}</li>`).join('')}
              </ul>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'ssl_certificate') {
        const fields = [
          ['Subject Common Name (CN)', data.subject_common_name],
          ['Issuer Common Name', data.issuer_common_name],
          ['Issuer Organization', data.issuer_organization],
          ['Valid From', data.valid_from],
          ['Valid Until', data.valid_until],
          ['Negotiated Protocol', data.protocol],
          ['Negotiated Cipher Suite', data.cipher_suite]
        ];
        let html = '<table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">';
        fields.forEach(([k, v]) => {
          if (!v) return;
          html += `
            <tr style="border-bottom: 1px solid #cbd5e1;">
              <td style="font-weight: bold; width: 35%; background-color: #f8fafc; padding: 10px 15px; color: #475569;">${k}</td>
              <td style="padding: 10px 15px; word-break: break-all; font-weight: bold;">${v}</td>
            </tr>
          `;
        });
        html += '</table>';

        if (data.subject_alternative_names?.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; background-color: #f8fafc; margin-bottom: 25px;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #475569; margin-bottom: 10px;">Subject Alternative Names (SANs)</div>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; font-family: monospace; font-size: 12px; font-weight: bold;">
                ${data.subject_alternative_names.map(san => `<span style="background: white; border: 1px solid #cbd5e1; padding: 4px 8px; border-radius: 4px; display: inline-block; margin-right: 6px; margin-bottom: 6px;">${san}</span>`).join('')}
              </div>
            </div>
          `;
        }

        if (data.supported_protocols && Object.keys(data.supported_protocols).length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">SUPPORTED TLS PROTOCOLS & CIPHERS</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 25%;">PROTOCOL</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left;">SUPPORTED CIPHER SUITES</th>
                  </tr>
                </thead>
                <tbody>
                  ${Object.entries(data.supported_protocols).map(([proto, ciphers]) => `
                    <tr style="border-bottom: 1px solid #e2e8f0; last:border-bottom: 0;">
                      <td style="padding: 10px 15px; vertical-align: top; font-weight: bold;">
                        <span style="background-color: #0d9488; color: white; padding: 3px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; display: inline-block;">${proto}</span>
                      </td>
                      <td style="padding: 10px 15px; font-family: monospace; font-size: 11px; font-weight: bold;">
                        <ul style="margin: 0; padding-left: 15px; line-height: 1.5; color: #334155;">
                          ${ciphers.map(c => `<li>${c}</li>`).join('')}
                        </ul>
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'geo_ip') {
        const fields = [
          ['IP Address', data.ip],
          ['Country', `${data.country} (${data.country_code || ''})`],
          ['Region', `${data.region} (${data.region_code || ''})`],
          ['City', data.city],
          ['Zipcode', data.postal_code],
          ['Latitude / Longitude', `${data.latitude || ''}, ${data.longitude || ''}`],
          ['Timezone', data.timezone],
          ['ISP', data.isp],
          ['Organization', data.organization],
          ['ASN', `${data.asn || ''} (${data.asn_name || ''})`],
          ['Reverse DNS', data.reverse_dns],
          ['Is Proxy / VPN', data.is_proxy ? 'Yes' : 'No'],
          ['Is Hosting Center', data.is_hosting ? 'Yes' : 'No'],
          ['Is Mobile Connection', data.is_mobile ? 'Yes' : 'No']
        ];
        let html = '<table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">';
        fields.forEach(([k, v]) => {
          if (v === undefined || v === null || v === '') return;
          html += `
            <tr style="border-bottom: 1px solid #cbd5e1;">
              <td style="font-weight: bold; width: 35%; background-color: #f8fafc; padding: 10px 15px; color: #475569;">${k}</td>
              <td style="padding: 10px 15px; word-break: break-all; font-weight: bold;">${v}</td>
            </tr>
          `;
        });
        html += '</table>';
        return html;
      }

      if (moduleKey === 'http_headers') {
        let html = `
          <div style="margin-bottom: 25px; border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; background-color: #f8fafc;">
            <div style="font-size: 13px; line-height: 1.6;">
              <strong>Target URL:</strong> <span style="font-family: monospace; font-weight: bold;">${data.url}</span><br>
              <strong>HTTP Status:</strong> <span style="font-weight: bold;">${data.http_status} ${data.reason || ''}</span><br>
              <strong>Response Time:</strong> <span style="font-weight: bold;">${data.response_time_ms} ms</span><br>
              <strong>Security Grade:</strong> <span style="background-color: #0d9488; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; display: inline-block; margin-top: 4px;">${data.security_grade || 'F'}</span>
            </div>
          </div>
        `;

        if (data.redirect_history?.length > 0) {
          html += `
            <div style="margin-bottom: 25px; border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; letter-spacing: 0.5px;">Redirect History</div>
              <ul style="margin: 0; padding-left: 20px; font-family: monospace; font-size: 12px; line-height: 1.6; font-weight: bold; color: #334155;">
                ${data.redirect_history.map(r => `<li>${r}</li>`).join('')}
                <li style="color: #0d9488;">${data.url}</li>
              </ul>
            </div>
          `;
        }

        if (data.all_headers && Object.keys(data.all_headers).length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">RAW RESPONSE HEADERS</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <tbody>
                  ${Object.entries(data.all_headers).map(([k, v]) => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 10px 15px; font-weight: bold; background-color: #f8fafc; width: 35%; color: #475569; font-family: monospace; border-right: 1px solid #e2e8f0;">${k}</td>
                      <td style="padding: 10px 15px; font-family: monospace; word-break: break-all; font-weight: bold; color: #334155;">${v}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }

        const securityHeaders = data.security_headers_present || {};
        const missingHeaders = data.security_headers_missing || [];

        html += `
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; background-color: #fcfdfa;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #166534; margin-bottom: 10px; letter-spacing: 0.5px;">Security Headers Configured (${Object.keys(securityHeaders).length})</div>
              <ul style="margin: 0; padding-left: 15px; font-size: 12px; line-height: 1.6; color: #166534; list-style: none;">
                ${Object.entries(securityHeaders).map(([k, v]) => {
                  const ideal = HEADER_IDEAL_CONFIGS?.[k] || HEADER_IDEAL_CONFIGS?.[k.toLowerCase()] || ''
                  return `
                    <li style="margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px dashed #e2e8f0;">
                      <strong style="color: #0f766e;">${k}:</strong> <span style="font-family: monospace; word-break: break-all; color: #1e293b;">${v}</span>
                      ${ideal ? `<div style="font-size: 11px; color: #047857; margin-top: 4px; font-family: monospace; background-color: #ecfdf5; padding: 3px 6px; border-radius: 4px;"><strong>Best Secure Configuration:</strong> ${ideal}</div>` : ''}
                    </li>
                  `
                }).join('')}
              </ul>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; background-color: #fdfcfa;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #991b1b; margin-bottom: 10px; letter-spacing: 0.5px;">Missing Security Headers (${missingHeaders.length})</div>
              <ul style="margin: 0; padding-left: 15px; font-size: 12px; line-height: 1.6; color: #991b1b; list-style: none;">
                ${missingHeaders.map(m => {
                  const ideal = HEADER_IDEAL_CONFIGS?.[m] || HEADER_IDEAL_CONFIGS?.[m.toLowerCase()] || ''
                  return `
                    <li style="margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px dashed #fee2e2;">
                      <strong style="color: #991b1b;">${m}</strong>
                      ${ideal ? `<div style="font-size: 11px; color: #047857; margin-top: 4px; font-family: monospace; background-color: #ecfdf5; padding: 3px 6px; border-radius: 4px;"><strong>Best Secure Configuration:</strong> ${ideal}</div>` : ''}
                    </li>
                  `
                }).join('')}
              </ul>
            </div>
          </div>
        `;
        return html;
      }

      if (moduleKey === 'web_technologies') {
        const components = data.detected_components || [];
        const tech = data.technologies || {};
        const metaTags = data.page_meta || {};
        const summary = data.tech_summary || {
          total_detected: components.length || Object.values(tech).flat().length,
          version_count: components.filter(c => c.version && c.version !== 'Unknown').length,
          categories_count: components.length ? new Set(components.map(c => c.category)).size : Object.keys(tech).length
        };
        
        let html = '';
        
        html += `
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 10px; padding: 15px; background-color: #f8fafc;">
              <div style="font-size: 10px; font-weight: bold; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Total Detected Technologies</div>
              <div style="font-size: 26px; font-weight: 900; color: #0f172a; margin-top: 4px;">${summary.total_detected}</div>
              <div style="font-size: 11px; color: #0d9488; font-weight: bold; margin-top: 2px;">${summary.categories_count} distinct categories</div>
            </div>
            <div style="border: 1px solid #ccfbf1; border-radius: 10px; padding: 15px; background-color: #f0fdfa;">
              <div style="font-size: 10px; font-weight: bold; color: #0f766e; text-transform: uppercase; letter-spacing: 0.5px;">Pinpointed Version Numbers</div>
              <div style="font-size: 26px; font-weight: 900; color: #0d9488; margin-top: 4px;">${summary.version_count}</div>
              <div style="font-size: 11px; color: #0f766e; font-weight: bold; margin-top: 2px;">${Math.round((summary.version_count / (summary.total_detected || 1)) * 100)}% version accuracy</div>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 10px; padding: 15px; background-color: #f8fafc;">
              <div style="font-size: 10px; font-weight: bold; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Target Web Server</div>
              <div style="font-size: 15px; font-weight: bold; color: #1e293b; margin-top: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${data.meta?.server || 'Not Advertised'}</div>
              <div style="font-size: 11px; color: #64748b; font-weight: bold; margin-top: 2px;">${data.meta?.powered_by ? 'Powered by: ' + data.meta.powered_by : 'HTTP Header Check'}</div>
            </div>
          </div>
        `;

        if (metaTags.title || metaTags.description) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 10px; padding: 15px; background-color: #ffffff; margin-bottom: 25px; font-size: 13px; line-height: 1.6; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #0f766e; margin-bottom: 8px; letter-spacing: 0.5px; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px;">Page Meta Details</div>
              <div style="margin-bottom: 4px;"><strong>Page Title:</strong> <span style="font-weight: bold; color: #0f172a;">${metaTags.title || '-'}</span></div>
              <div style="margin-bottom: 4px;"><strong>Meta Description:</strong> <span style="font-weight: 500; color: #334155;">${metaTags.description || '-'}</span></div>
              ${metaTags.canonical_url ? `<div><strong>Canonical URL:</strong> <span style="font-family: monospace; font-weight: bold; color: #0d9488;">${metaTags.canonical_url}</span></div>` : ''}
            </div>
          `;
        }

        if (components.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.03);">
              <div style="background-color: #f1f5f9; padding: 12px 18px; font-weight: 800; font-size: 12px; letter-spacing: 0.5px; color: #1e293b; border-bottom: 1px solid #cbd5e1; display: flex; justify-content: space-between; align-items: center;">
                <span>DETECTED SOFTWARE STACK & FINGERPRINTS</span>
                <span style="font-size: 11px; color: #0d9488; font-weight: bold;">${components.length} Items</span>
              </div>
              <table style="width: 100%; border-collapse: collapse; font-size: 13px; background: white;">
                <thead>
                  <tr style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0; font-size: 10px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px;">
                    <th style="padding: 10px 15px; text-align: left; width: 22%;">Technology</th>
                    <th style="padding: 10px 15px; text-align: left; width: 15%;">Version</th>
                    <th style="padding: 10px 15px; text-align: left; width: 22%;">Category</th>
                    <th style="padding: 10px 15px; text-align: center; width: 14%;">Confidence</th>
                    <th style="padding: 10px 15px; text-align: left; width: 27%;">Detection Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  ${components.map((c, i) => {
                    const hasVer = c.version && c.version !== 'Unknown';
                    return `
                      <tr style="border-bottom: 1px solid #f1f5f9; background-color: ${i % 2 === 0 ? '#ffffff' : '#fafafa'};">
                        <td style="padding: 12px 15px; font-weight: 800; color: #0f172a;">
                          <div style="font-size: 14px;">${c.name}</div>
                          ${c.description ? `<div style="font-size: 11px; font-weight: normal; color: #64748b; margin-top: 2px;">${c.description}</div>` : ''}
                        </td>
                        <td style="padding: 12px 15px;">
                          ${hasVer ? `
                            <span style="background-color: #0d9488; color: white; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 900; font-family: monospace; display: inline-block; box-shadow: 0 1px 2px rgba(13,148,136,0.3);">
                              v${c.version}
                            </span>
                          ` : `
                            <span style="background-color: #f1f5f9; color: #64748b; border: 1px solid #e2e8f0; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; font-family: monospace; display: inline-block;">
                              Unknown
                            </span>
                          `}
                        </td>
                        <td style="padding: 12px 15px;">
                          <span style="background-color: #fef3c7; color: #92400e; border: 1px solid #fde68a; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 800; display: inline-block;">
                            ${c.category_label || c.category}
                          </span>
                        </td>
                        <td style="padding: 12px 15px; text-align: center;">
                          <span style="background-color: ${c.confidence === 'High' ? '#dcfce7' : '#fef3c7'}; color: ${c.confidence === 'High' ? '#166534' : '#92400e'}; border: 1px solid ${c.confidence === 'High' ? '#bbf7d0' : '#fde68a'}; padding: 3px 8px; border-radius: 9999px; font-size: 10px; font-weight: 800; display: inline-block;">
                            ${c.confidence || 'Medium'}
                          </span>
                        </td>
                        <td style="padding: 12px 15px; font-family: monospace; font-size: 11px; color: #475569; word-break: break-all;">
                          ${c.matched_by || 'Pattern signature match'}
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          `;
        } else {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">DETECTED SOFTWARE STACK</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <tbody>
                  ${Object.entries(tech).map(([category, items]) => {
                    if (!items || items.length === 0) return '';
                    return `
                      <tr style="border-bottom: 1px solid #e2e8f0; last:border-bottom: 0;">
                        <td style="padding: 12px 15px; font-weight: bold; background-color: #f8fafc; width: 35%; color: #475569; border-right: 1px solid #cbd5e1;">${category.replace(/_/g, ' ').toUpperCase()}</td>
                        <td style="padding: 12px 15px; font-weight: bold;">
                          ${items.map(item => `<span style="background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 6px; display: inline-block; margin-bottom: 4px; color: #0f766e;">${item}</span>`).join('')}
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          `;
        }

        if (data.external_domains?.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 10px; padding: 15px; background: white;">
              <div style="font-weight: 800; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; letter-spacing: 0.5px;">Loaded Third-Party Domains (${data.external_domain_count})</div>
              <div style="display: flex; flex-wrap: wrap; gap: 6px; font-family: monospace; font-size: 11px; font-weight: bold;">
                ${data.external_domains.map(d => `<span style="background: #f8fafc; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; display: inline-block; color: #334155;">${d}</span>`).join('')}
              </div>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'abuseipdb') {
        const reports = data.reports || [];
        const score = data.abuse_confidence_score || data.abuseConfidenceScore || 0;
        let html = `
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; background-color: #f8fafc; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: 0.5px;">Abuse Confidence Rating</div>
              <div style="font-size: 36px; font-weight: 900; color: ${score > 10 ? '#b91c1c' : '#166534'}; margin: 10px 0;">${score}%</div>
              <span style="background-color: ${score > 10 ? '#fee2e2' : '#dcfce7'}; color: ${score > 10 ? '#b91c1c' : '#166534'}; padding: 4px 12px; border-radius: 9999px; font-size: 10px; font-weight: bold;">
                ${score > 10 ? 'SUSPICIOUS' : 'CLEAN'}
              </span>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; font-size: 13px; line-height: 1.8; font-weight: bold; color: #334155;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px;">IP Info Summary</div>
              <strong>IP Address:</strong> ${data.ipAddress || data.ip || '-'}<br>
              <strong>ISP:</strong> ${data.isp || '-'}<br>
              <strong>Usage Type:</strong> ${data.usage_type || data.usageType || '-'}<br>
              <strong>Domain Name:</strong> ${data.domain || '-'}<br>
              <strong>Hostname(s):</strong> ${Array.isArray(data.hostnames) ? data.hostnames.join(', ') : (data.hostnames || '-')}<br>
              <strong>Country:</strong> ${data.country_name || data.countryName || '-'}<br>
              <strong>Total Spam Reports:</strong> ${data.total_reports || data.totalReports || 0}<br>
              <strong>Is Whitelisted:</strong> ${data.is_whitelisted || data.isWhitelisted ? 'Yes' : 'No'}
            </div>
          </div>
        `;

        if (reports.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">ABUSE REPORTS HISTORY</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 25%;">TIMESTAMP</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 20%;">CATEGORIES</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left;">REPORTER COMMENT</th>
                  </tr>
                </thead>
                <tbody>
                  ${reports.map(rep => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 10px 15px; font-family: monospace; white-space: nowrap; font-weight: bold;">${rep.reportedAt || rep.date}</td>
                      <td style="padding: 10px 15px; font-weight: bold;">${rep.categories?.join(', ') || '-'}</td>
                      <td style="padding: 10px 15px; font-style: italic; color: #475569; font-weight: bold;">${rep.comment || '-'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'virustotal') {
        const stats = data.detection_stats || data.last_analysis_stats || data.lastAnalysisStats || {};
        const totalEngines = stats.total_engines || Object.values(stats).reduce((a, b) => a + b, 0) || 91;
        const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);
        
        let html = `
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; background-color: #f8fafc; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: 0.5px;">AV Engines Detection Ratio</div>
              <div style="font-size: 36px; font-weight: 900; color: ${maliciousCount > 0 ? '#b91c1c' : '#166534'}; margin: 10px 0;">${maliciousCount} / ${totalEngines}</div>
              <span style="background-color: ${maliciousCount > 0 ? '#fee2e2' : '#dcfce7'}; color: ${maliciousCount > 0 ? '#b91c1c' : '#166534'}; padding: 4px 12px; border-radius: 9999px; font-size: 10px; font-weight: bold;">
                ${maliciousCount > 0 ? `${maliciousCount} ENGINES FLAGGED` : 'UNDETECTED / CLEAN'}
              </span>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; font-size: 13px; line-height: 1.8; font-weight: bold; color: #334155;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px;">Analysis Engines Breakdowns</div>
              <strong>Harmless Engines:</strong> ${stats.harmless || 0}<br>
              <strong>Undetected Engines:</strong> ${stats.undetected || 0}<br>
              <strong>Suspicious Engines:</strong> ${stats.suspicious || 0}<br>
              <strong>Malicious Engines:</strong> ${stats.malicious || 0}<br>
              <strong>Community Reputation Score:</strong> ${data.reputation !== undefined ? data.reputation : 0}
            </div>
          </div>
        `;

        if (data.flagged_by?.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">
              <div style="background-color: #fee2e2; color: #991b1b; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; border-bottom: 1px solid #cbd5e1;">MALICIOUS / SUSPICIOUS THREAT DETECTIONS</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background-color: #fff8f8; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 8px 12px; font-weight: bold; text-align: left; color: #991b1b; width: 30%;">SECURITY ENGINE</th>
                    <th style="padding: 8px 12px; font-weight: bold; text-align: left; color: #991b1b; width: 25%;">CATEGORY</th>
                    <th style="padding: 8px 12px; font-weight: bold; text-align: left; color: #991b1b;">RESULT / DETECTION DETAILED</th>
                  </tr>
                </thead>
                <tbody>
                  ${data.flagged_by.map(f => `
                    <tr style="border-bottom: 1px solid #fee2e2;">
                      <td style="padding: 8px 12px; font-weight: bold; color: #1e293b;">${f.engine}</td>
                      <td style="padding: 8px 12px; font-weight: bold; color: #b91c1c; text-transform: uppercase;">${f.category}</td>
                      <td style="padding: 8px 12px; font-family: monospace; font-weight: bold; color: #475569;">${f.result || 'detected'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }

        if (data.tags?.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 25px;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; letter-spacing: 0.5px;">Security Intel Tags</div>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; font-family: monospace; font-size: 11px; font-weight: bold;">
                ${data.tags.map(tag => `<span style="background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 4px 8px; border-radius: 4px; color: #475569; display: inline-block; margin-right: 6px; margin-bottom: 6px;">${tag}</span>`).join('')}
              </div>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'port_scan') {
        const ports = data.open_ports || data.ports || [];
        let html = `<p style="font-size: 13px; font-weight: bold;"><strong>Scan Target IP:</strong> ${data.ip_address || data.target_ip || '-'}</p>`;
        if (ports.length === 0) {
          html += `<div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; text-align: center; color: #64748b; font-style: italic; font-size: 13px;">No open ports identified in the scan.</div>`;
        } else {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-top: 15px;">
              <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                  <tr style="background-color: #f1f5f9; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 15%; color: #475569;">PORT</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 15%; color: #475569;">STATE</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 25%; color: #475569;">SERVICE</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; color: #475569;">SERVICE BANNER / VERSION</th>
                  </tr>
                </thead>
                <tbody>
                  ${ports.map(p => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 12px 15px; font-family: monospace; font-weight: bold; color: #0f172a;">${p.port}</td>
                      <td style="padding: 12px 15px;"><span style="background-color: #dcfce7; color: #166534; font-size: 10px; font-weight: bold; padding: 3px 8px; border-radius: 4px; display: inline-block;">${p.state || 'open'}</span></td>
                      <td style="padding: 12px 15px; font-weight: bold; color: #0d9488;">${p.service || 'unknown'}</td>
                      <td style="padding: 12px 15px; font-family: monospace; font-size: 12px; color: #475569; word-break: break-all; font-weight: bold;">${p.banner || p.version || '-'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'subdomains') {
        const subs = data.subdomains || [];
        let html = `<p style="font-size: 13px; font-weight: bold;"><strong>Total Subdomains Discovered:</strong> ${data.count || subs.length} | <strong>Active:</strong> ${data.active_count || 0}</p>`;
        if (subs.length === 0) {
          html += `<div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; text-align: center; color: #64748b; font-style: italic; font-size: 13px;">No subdomains discovered.</div>`;
        } else {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-top: 15px;">
              <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                  <tr style="background-color: #f1f5f9; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 45%; color: #475569;">SUBDOMAIN</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 25%; color: #475569;">RESOLVED IP</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; color: #475569;">DISCOVERY SOURCE</th>
                  </tr>
                </thead>
                <tbody>
                  ${subs.map(s => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 12px 15px; font-family: monospace; font-weight: bold; word-break: break-all; color: #0d9488;">${s.subdomain}</td>
                      <td style="padding: 12px 15px; font-family: monospace; color: ${s.ip ? '#334155' : '#94a3b8'}; font-weight: bold;">${s.ip || 'Unresolved'}</td>
                      <td style="padding: 12px 15px; font-size: 11px; color: #64748b; font-weight: bold;">${s.source || '-'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'directories') {
        const paths = data.found || [];
        let html = `<p style="font-size: 13px; font-weight: bold;"><strong>Directories Probed:</strong> ${data.paths_checked || 0} | <strong>Discovered Paths:</strong> ${paths.length}</p>`;
        if (paths.length === 0) {
          html += `<div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; text-align: center; color: #64748b; font-style: italic; font-size: 13px;">No directories or files found.</div>`;
        } else {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden; margin-top: 15px;">
              <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                  <tr style="background-color: #f1f5f9; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 45%; color: #475569;">URL PATH</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 15%; color: #475569;">STATUS</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; width: 20%; color: #475569;">CONTENT TYPE</th>
                    <th style="padding: 12px 15px; font-weight: bold; text-align: left; color: #475569;">RESPONSE SNIPPET</th>
                  </tr>
                </thead>
                <tbody>
                  ${paths.map(p => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 12px 15px; font-family: monospace; font-weight: bold; word-break: break-all;"><a href="${p.url}" target="_blank" style="color: #0d9488; text-decoration: none;">${p.path}</a></td>
                      <td style="padding: 12px 15px; font-family: monospace; font-weight: bold; color: ${p.status === 200 ? '#166534' : '#b91c1c'};">${p.status}</td>
                      <td style="padding: 12px 15px; font-size: 12px; color: #64748b; font-family: monospace; font-weight: bold;">${p.content_type || '-'}</td>
                      <td style="padding: 12px 15px; font-family: monospace; font-size: 11px; color: #64748b; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: bold;">${p.snippet || '-'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'reverse_dns') {
        const fields = [
          ['Resolved IP', data.ip],
          ['Reverse Pointer hostname (PTR)', data.hostname || data.reverse_dns],
          ['System Resolver Resolution', data.system_resolver_ptr || 'Failed'],
          ['Nslookup Resolver Resolution', data.nslookup_resolver_ptr || 'Failed']
        ];
        let html = '<table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">';
        fields.forEach(([k, v]) => {
          html += `
            <tr style="border-bottom: 1px solid #cbd5e1;">
              <td style="font-weight: bold; width: 35%; background-color: #f8fafc; padding: 10px 15px; color: #475569;">${k}</td>
              <td style="padding: 10px 15px; font-family: monospace; font-weight: bold;">${v}</td>
            </tr>
          `;
        });
        html += '</table>';
        return html;
      }

      if (moduleKey === 'cloud_provider') {
        const fields = [
          ['Cloud Hosting Detected', data.cloud_detected ? 'Yes' : 'No'],
          ['Hosting Provider Name', data.provider || 'None / On-Premise'],
          ['Confidence Score', data.confidence || 'low'],
          ['Detection Method', data.method || '-'],
          ['ASN Registry Organization', data.asn_org],
          ['ASN Registered ISP', data.asn_isp],
          ['AS Number', data.as_number],
          ['Is Data Center IP', data.is_hosting ? 'Yes' : 'No']
        ];
        let html = '<table class="kv-table" style="width: 100%; border-collapse: collapse; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">';
        fields.forEach(([k, v]) => {
          if (v === undefined || v === null) return;
          html += `
            <tr style="border-bottom: 1px solid #cbd5e1;">
              <td style="font-weight: bold; width: 35%; background-color: #f8fafc; padding: 10px 15px; color: #475569;">${k}</td>
              <td style="padding: 10px 15px; font-weight: bold;">${v}</td>
            </tr>
          `;
        });
        html += '</table>';
        return html;
      }

      if (moduleKey === 'waf_detect') {
        const probes = data.probes || [];
        const detections = data.all_detected || data.detections || [];
        let html = `
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; background-color: #f8fafc; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: 0.5px;">WAF Presence Detections</div>
              <div style="font-size: 26px; font-weight: 900; color: ${data.waf_detected ? '#0d9488' : '#64748b'}; margin: 10px 0;">${data.waf_detected ? (data.waf_name || 'Detected') : 'Not Found'}</div>
              <span style="background-color: ${data.waf_detected ? '#dcfce7' : '#f1f5f9'}; color: ${data.waf_detected ? '#166534' : '#64748b'}; padding: 4px 12px; border-radius: 9999px; font-size: 10px; font-weight: bold;">
                ${data.waf_detected ? 'ACTIVE FIREWALL PROTECTED' : 'UNPROTECTED'}
              </span>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; font-size: 13px; line-height: 2.0; font-weight: bold; color: #334155;">
              <strong>Confidence level:</strong> ${data.confidence || 'none'}<br>
              <strong>Probes Sent:</strong> ${data.total_probes || probes.length || 0}<br>
              <strong>Probes Blocked:</strong> ${data.probes_blocked || 0}
            </div>
          </div>
        `;

        if (detections.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 25px;">
              <div style="font-weight: bold; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 10px; letter-spacing: 0.5px;">Detected WAF Vendor Details</div>
              <ul style="margin: 0; padding-left: 20px; font-size: 13px; font-weight: bold; color: #334155;">
                ${detections.map(d => `<li><strong>${d.waf_name || d}:</strong> ${d.reason || d.evidence || ''}</li>`).join('')}
              </ul>
            </div>
          `;
        }

        if (probes.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">WAF PROBE FIREWALL RESPONSES</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 15%; color: #475569;">PROBE TYPE</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 15%; color: #475569;">HTTP STATUS</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 20%; color: #475569;">WAF SIGNALS</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; color: #475569;">Fuzzed URL Tested</th>
                  </tr>
                </thead>
                <tbody>
                  ${probes.map(p => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 10px 15px; font-weight: bold;">${p.probe}</td>
                      <td style="padding: 10px 15px; font-family: monospace; font-weight: bold; color: ${p.status_code >= 400 ? '#b91c1c' : '#166534'};">${p.status_code}</td>
                      <td style="padding: 10px 15px; font-weight: bold;">${p.waf_signals || 0}</td>
                      <td style="padding: 10px 15px; font-family: monospace; font-size: 11px; word-break: break-all; color: #64748b; font-weight: bold;">${p.url}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'cms_fingerprint') {
        const cms = data.all_detected || data.detections || [];
        let html = `
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; background-color: #f8fafc; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: 0.5px;">CMS Detection Result</div>
              <div style="font-size: 26px; font-weight: 900; color: ${data.cms_detected ? '#0d9488' : '#64748b'}; margin: 10px 0;">${data.cms_detected ? (data.cms_name || 'Detected') : 'Not Identified'}</div>
              <span style="background-color: ${data.cms_detected ? '#dcfce7' : '#f1f5f9'}; color: ${data.cms_detected ? '#166534' : '#64748b'}; padding: 4px 12px; border-radius: 9999px; font-size: 10px; font-weight: bold;">
                ${data.cms_detected ? `CMS DETECTED (Version: ${data.version || 'Unknown'})` : 'NO CORE CMS'}
              </span>
            </div>
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; font-size: 13px; line-height: 2.0; font-weight: bold; color: #334155;">
              <strong>Confidence score:</strong> ${data.confidence || 'none'}<br>
              <strong>Generator Header Tag:</strong> ${data.generator_tag || '-'}<br>
              <strong>Paths Probed:</strong> ${data.paths_probed || 0}
            </div>
          </div>
        `;

        if (cms.length > 0) {
          html += `
            <div style="border: 1px solid #cbd5e1; border-radius: 8px; overflow: hidden;">
              <div style="background-color: #f1f5f9; padding: 10px 15px; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; color: #475569; border-bottom: 1px solid #cbd5e1;">CMS EVIDENCE DETECTED</div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;">
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 25%; color: #475569;">CMS NAME</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; width: 20%; color: #475569;">CONFIDENCE</th>
                    <th style="padding: 10px 15px; font-weight: bold; text-align: left; color: #475569;">FINGERPRINT EVIDENCE LIST</th>
                  </tr>
                </thead>
                <tbody>
                  ${cms.map(c => `
                    <tr style="border-bottom: 1px solid #cbd5e1; last:border-bottom: 0;">
                      <td style="padding: 10px 15px; font-weight: bold; color: #0d9488;">${c.cms_name}</td>
                      <td style="padding: 10px 15px; font-weight: bold;">${c.confidence}</td>
                      <td style="padding: 10px 15px; font-size: 12px; color: #64748b; font-weight: bold;">
                        <ul style="margin: 0; padding-left: 15px;">
                          ${c.evidence?.map(e => `<li>${e}</li>`).join('') || ''}
                        </ul>
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
        return html;
      }

      if (moduleKey === 'http_availability') {
        const http = data.http || {};
        const https = data.https || {};
        const okColor = (ok) => ok ? '#166534' : '#b91c1c';
        const okBg = (ok) => ok ? '#dcfce7' : '#fee2e2';

        const portCard = (label, port, res) => `
          <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px;">
            <div style="font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px;">${label} (Port ${port})</div>
            <span style="background-color: ${res.blocked_by_waf ? '#fef3c7' : okBg(res.accessible)}; color: ${res.blocked_by_waf ? '#b45309' : okColor(res.accessible)}; padding: 4px 12px; border-radius: 9999px; font-size: 10px; font-weight: bold; display: inline-block; margin-bottom: 10px;">
              ${res.blocked_by_waf ? 'WAF CHALLENGE' : res.accessible ? 'ACCESSIBLE' : 'NOT ACCESSIBLE'}
            </span>
            ${res.blocked_by_waf ? `<div style="font-size: 12px; font-weight: bold; color: #b45309; margin-bottom: 10px;">${res.waf_note}</div>` : ''}
            <div style="font-size: 13px; line-height: 2.0; font-weight: bold; color: #334155;">
              ${res.port_state ? `<strong>Port Status:</strong> <span style="background-color: #f1f5f9; color: #475569; padding: 2px 10px; border-radius: 9999px; font-size: 10px; font-weight: bold; text-transform: uppercase;">${res.port_state}</span><br>` : ''}
              ${res.accessible ? `
                <strong>Status Code:</strong> ${res.status_code}<br>
                <strong>HTTP Version:</strong> ${res.http_version || 'Unknown'}<br>
                <strong>Response Time:</strong> ${res.response_time_ms}ms<br>
                ${res.redirects_to ? `<strong>Redirects To:</strong> ${res.redirects_to}<br>` : ''}
                ${res.redirect_count > 0 && !res.blocked_by_waf ? `<strong>Redirect Hops:</strong> ${res.redirect_count}<br><strong>Final URL:</strong> ${res.final_url}<br><strong>Final Status:</strong> ${res.final_status_code}<br>` : ''}
                ${res.hsts ? `<strong>HSTS:</strong> max-age=${res.hsts.max_age_seconds ?? '?'}${res.hsts.include_subdomains ? ', includeSubDomains' : ''}${res.hsts.preload ? ', preload' : ''}<br>` : ''}
              ` : `
                <strong>Reason:</strong> ${res.error_message || 'Unknown error'}
              `}
            </div>
          </div>
        `;

        return `
          <div style="border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 25px; background-color: #f8fafc;">
            <div style="font-size: 13px; font-weight: bold; color: #334155;">${data.summary || ''}</div>
          </div>
          <div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px;">
            ${portCard('HTTP', 80, http)}
            ${portCard('HTTPS', 443, https)}
          </div>
        `;
      }

      if (moduleKey === 'email_gather') {
        const emails = data.emails || [];
        const sources = data.sources || {};
        const highConf = emails.filter(e => e.confidence === 'high');
        const medConf  = emails.filter(e => e.confidence === 'medium');

        const sourceColors = {
          crt_sh: '#3b82f6', pgp_keyserver: '#8b5cf6', ubuntu_pgp: '#a855f7', mit_pgp: '#6366f1',
          wayback_machine: '#f59e0b', wayback_docs: '#d97706', web_crawl: '#10b981', dns_txt_dmarc: '#06b6d4',
          subdomain_dns: '#0284c7', github_search: '#1d4ed8', bing_search: '#eab308', commoncrawl: '#7c3aed',
          alienvault_otx: '#ec4899', threatminer: '#ef4444', urlscan: '#f97316', certspotter: '#14b8a6',
          keybase: '#3b82f6', email_format: '#0284c7', skymem: '#6366f1', smtp_banner: '#64748b',
          ahmia_darkweb: '#dc2626', paste_dumps: '#ea580c', leakix: '#b91c1c', forum_registrations: '#4f46e5'
        };
        const sourceLabel = {
          crt_sh: 'crt.sh', pgp_keyserver: 'OpenPGP', ubuntu_pgp: 'Ubuntu PGP', mit_pgp: 'MIT PGP',
          wayback_machine: 'Wayback', wayback_docs: 'Wayback Docs', web_crawl: 'Web Crawl', dns_txt_dmarc: 'DNS/DMARC',
          subdomain_dns: 'Subdomain DNS', github_search: 'GitHub', bing_search: 'Bing', commoncrawl: 'CommonCrawl',
          alienvault_otx: 'AlienVault OTX', threatminer: 'ThreatMiner', urlscan: 'URLScan', certspotter: 'CertSpotter',
          keybase: 'Keybase', email_format: 'Email-Format', skymem: 'Skymem', smtp_banner: 'SMTP Banner',
          ahmia_darkweb: 'Ahmia Darkweb', paste_dumps: 'Paste Dumps', leakix: 'LeakIX', forum_registrations: 'Forums & Events'
        };

        const badgeFor = (src) => {
          const col = sourceColors[src] || '#64748b';
          const lbl = sourceLabel[src] || src;
          return `<span style="background-color: ${col}20; color: ${col}; font-size: 10px; font-weight: bold; padding: 2px 7px; border-radius: 4px; display: inline-block; margin: 1px;">${lbl}</span>`;
        };

        const empCount = data.employee_accounts_count || emails.filter(e => e.account_type === 'employee').length;
        const rCount = data.role_accounts_count || emails.filter(e => e.account_type === 'role').length;
        const lkCount = data.leaked_accounts_count || emails.filter(e => e.is_leaked).length;

        let html = `
          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 12px; margin-bottom: 20px;">
            <div style="border: 1px solid #ede9fe; border-radius: 8px; padding: 14px; background: #faf5ff; text-align: center;">
              <div style="font-size: 10px; font-weight: bold; color: #7c3aed; text-transform: uppercase;">Total Found</div>
              <div style="font-size: 26px; font-weight: 900; color: #5b21b6; margin: 4px 0;">${data.total_found || 0}</div>
              <div style="font-size: 10px; color: #6d28d9;">unique emails</div>
            </div>
            <div style="border: 1px solid #dbeafe; border-radius: 8px; padding: 14px; background: #eff6ff; text-align: center;">
              <div style="font-size: 10px; font-weight: bold; color: #2563eb; text-transform: uppercase;">Employee Accounts</div>
              <div style="font-size: 26px; font-weight: 900; color: #1d4ed8; margin: 4px 0;">${empCount}</div>
              <div style="font-size: 10px; color: #1e40af;">individual staff</div>
            </div>
            <div style="border: 1px solid #ccfbf1; border-radius: 8px; padding: 14px; background: #f0fdf4; text-align: center;">
              <div style="font-size: 10px; font-weight: bold; color: #0d9488; text-transform: uppercase;">Role Accounts</div>
              <div style="font-size: 26px; font-weight: 900; color: #0f766e; margin: 4px 0;">${rCount}</div>
              <div style="font-size: 10px; color: #115e59;">group / admin</div>
            </div>
            <div style="border: 1px solid #ffe4e6; border-radius: 8px; padding: 14px; background: #fff1f2; text-align: center;">
              <div style="font-size: 10px; font-weight: bold; color: #e11d48; text-transform: uppercase;">Leaked / Exposed</div>
              <div style="font-size: 26px; font-weight: 900; color: #be123c; margin: 4px 0;">${lkCount}</div>
              <div style="font-size: 10px; color: #9f1239;">leak exposure</div>
            </div>
          </div>
        `;

        if (emails.length === 0) {
          html += '<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; background: #f8fafc; color: #64748b; text-align: center; font-weight: bold;">No email addresses discovered for this domain.</div>';
        } else {
          html += `
            <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 20px;">
              <div style="background: #f8fafc; padding: 12px 16px; font-size: 11px; font-weight: bold; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">
                Discovered Email Addresses (${emails.length})
              </div>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                  <tr style="background: #f1f5f9; border-bottom: 1px solid #e2e8f0;">
                    <th style="padding: 10px 16px; text-align: left; font-weight: bold; color: #475569; width: 60%;">EMAIL ADDRESS</th>
                    <th style="padding: 10px 16px; text-align: right; font-weight: bold; color: #475569; width: 40%;">SOURCES</th>
                  </tr>
                </thead>
                <tbody>
                  ${emails.map((e, i) => `
                    <tr style="border-bottom: 1px solid #f1f5f9; background: ${i % 2 === 0 ? '#ffffff' : '#fafafa'};">
                      <td style="padding: 10px 16px; font-family: monospace; font-size: 12px; color: #1e293b; font-weight: bold;">${e.email}</td>
                      <td style="padding: 10px 16px; text-align: right;">${(e.sources || []).map(badgeFor).join('')}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }



        return html;
      }

      return '<pre style="font-family: monospace; font-size: 12px; background-color: #f8fafc; border: 1px solid #cbd5e1; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; font-weight: bold;">' + JSON.stringify(data, null, 2) + '</pre>';
    };

    let targetReports = '';
    targets.forEach(t => {
      if (!t) return;
      const targetName = t.target;
      const moduleResult = t.results?.[moduleKey] || t[moduleKey];
      
      let contentHtml = '';
      if (t.error) {
        contentHtml = `<div class="error-box" style="border: 1px solid #fee2e2; background-color: #fff5f5; color: #991b1b; padding: 20px; border-radius: 8px;"><h3>Diagnostics Failed</h3><p>${t.error}</p></div>`;
      } else if (!moduleResult) {
        contentHtml = `<div class="skipped-box" style="border: 1px solid #cbd5e1; background-color: #f8fafc; color: #64748b; padding: 20px; border-radius: 8px;"><h3>No Data</h3><p>No diagnostics data returned for this module.</p></div>`;
      } else if (moduleResult.status === 'error') {
        contentHtml = `<div class="error-box" style="border: 1px solid #fee2e2; background-color: #fff5f5; color: #991b1b; padding: 20px; border-radius: 8px;"><h3>Diagnostics Failed</h3><p>${moduleResult.error_message || 'Unknown error'}</p></div>`;
      } else if (moduleResult.status === 'skipped') {
        contentHtml = `<div class="skipped-box" style="border: 1px solid #cbd5e1; background-color: #f8fafc; color: #64748b; padding: 20px; border-radius: 8px;"><h3>Module Skipped</h3><p>${moduleResult.reason || 'Not configured'}</p></div>`;
      } else {
        contentHtml = getModuleHtml(moduleKey, moduleResult);
      }

      targetReports += `
        <div class="target-card" style="background: white; border: 1px solid #cbd5e1; border-radius: 12px; margin-bottom: 40px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); overflow: visible;">
          <div class="target-header" style="background-color: #f1f5f9; padding: 18px 25px; border-bottom: 2px solid #cbd5e1; font-weight: 800; font-size: 15px; color: #1e293b; border-top-left-radius: 12px; border-top-right-radius: 12px; letter-spacing: 0.5px;">
            TARGET HOST: ${targetName}
          </div>
          <div class="target-body" style="padding: 25px;">
            ${contentHtml}
          </div>
        </div>
      `;
    });

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${meta.title} Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #f8fafc;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #0d9488 0%, #0f766e 100%);
            color: white;
            padding: 35px;
            border-radius: 16px;
            margin-bottom: 40px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
        }
        .header h1 {
            margin: 0;
            font-size: 26px;
            font-weight: 800;
            letter-spacing: -0.5px;
        }
        .header p {
            margin: 10px 0 0 0;
            color: #ccfbf1;
            font-size: 13px;
            font-weight: 600;
        }
        .empty {
            color: #94a3b8;
            font-style: italic;
        }
        .badge {
            font-size: 9px;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .badge.true {
            background-color: #dcfce7;
            color: #166534;
        }
        .badge.false {
            background-color: #fee2e2;
            color: #991b1b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>${meta.title} Diagnostic Report</h1>
            <p>Generated on ${new Date().toLocaleString()} | Reconnaissance Tool</p>
        </div>
        ${targetReports}
    </div>
</body>
</html>`;
  };

  const downloadIndividualReport = () => {
    const htmlContent = generateHtmlReport()
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    
    const targetStr = isBatch
      ? `${scanData.results.length}_targets`
      : scanData.target || inputVal
      
    a.download = `${moduleKey}_report_${targetStr}_${Date.now()}.html`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const renderSingleWidget = (targetName, moduleResult, targetError = null) => {
    if (targetError) {
      return (
        <div className="border border-red-200 bg-red-50/20 rounded-2xl p-6 glow-red text-red-750 font-semibold mt-4">
          <div className="font-bold uppercase tracking-wider text-xs mb-1.5">Scan Execution Failed ({targetName})</div>
          <div className="text-xs font-mono break-all">{targetError}</div>
        </div>
      )
    }
    if (!moduleResult) return null

    if (moduleResult.status === 'error') {
      if (moduleResult.error_code === 'api_key_missing' || moduleResult.error_code === 'unauthorized') {
        return (
          <div className="border border-amber-250 border-amber-300 bg-amber-50/20 rounded-2xl p-6 text-slate-800 mt-6 font-semibold space-y-4 shadow-sm">
            <div className="flex items-center gap-2 text-amber-700 font-extrabold uppercase tracking-widest text-xs">
              <Lock className="w-4.5 h-4.5 text-amber-600" />
              API Key Error ({targetName})
            </div>
            <p className="text-xs leading-relaxed text-slate-600 font-medium">
              {moduleResult.error_message || 'A valid API key is required for this diagnostic module.'}
            </p>
            <div className="border-t border-amber-100/50 pt-4">
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  const retryVal = e.target.elements.retryKey.value.trim()
                  if (!retryVal) return
                  handleApiKeyChange(retryVal)
                  onStartScan(inputVal.trim(), retryVal)
                }}
                className="flex flex-col sm:flex-row gap-2"
              >
                <input
                  type="password"
                  name="retryKey"
                  placeholder="Enter API Key"
                  defaultValue={apiKey}
                  className="flex-1 px-4 py-3 text-xs font-normal border border-slate-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 bg-white"
                />
                <button
                  type="submit"
                  className="px-6 py-3 text-xs font-extrabold text-white uppercase tracking-wider bg-amber-600 hover:bg-amber-700 rounded-xl transition duration-150"
                >
                  Submit Key & Scan
                </button>
              </form>
            </div>
          </div>
        )
      }
      return (
        <div className="border border-red-200 bg-red-50/20 rounded-2xl p-6 glow-red text-red-700 mt-6 font-semibold">
          <div className="font-bold uppercase tracking-wider text-xs mb-1.5">Module Diagnostics Failed ({targetName})</div>
          <div className="text-xs font-mono break-all">{moduleResult.error_message || 'Timeout or invalid host query.'}</div>
        </div>
      )
    }

    if (moduleResult.status === 'skipped') {
      return (
        <div className="border border-slate-200 bg-slate-50/40 rounded-2xl p-6 text-slate-500 mt-6 font-semibold">
          <div className="font-bold uppercase tracking-wider text-xs mb-1.5">Module Skipped ({targetName})</div>
          <div className="text-xs leading-relaxed">{moduleResult.reason || 'Not configured.'}</div>
        </div>
      )
    }

    switch (moduleKey) {
      case 'dns_records':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Active DNS Mapping</h4>
            {moduleResult?.resolved_via_ptr && (
              <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 mb-4">
                <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-amber-800 font-semibold leading-relaxed">
                  {moduleResult.ptr_note}
                </p>
              </div>
            )}
            <DnsSection data={moduleResult} />
          </div>
        )
      case 'whois':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">WHOIS Registrar Information</h4>
            <WhoisSection data={moduleResult} />
          </div>
        )
      case 'ssl_certificate':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">SSL/TLS Security Metrics</h4>
            {moduleResult?.checked_via_raw_ip && (
              <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 mb-4">
                <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-amber-800 font-semibold leading-relaxed">
                  {moduleResult.ip_sni_note}
                </p>
              </div>
            )}
            <SslSection data={moduleResult} />
          </div>
        )
      case 'geo_ip':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">IP Geolocation Metrics</h4>
            <GeoSection data={moduleResult} />
          </div>
        )
      case 'http_headers':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">HTTP Target Headers</h4>
            <HeadersSection data={moduleResult} />
          </div>
        )
      case 'web_technologies':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Web stack Detections</h4>
            <TechSection data={moduleResult} />
          </div>
        )
      case 'abuseipdb':
        return (
          <div className="mt-6">
            <AbuseIpdbCard data={moduleResult} />
          </div>
        )
      case 'virustotal':
        return (
          <div className="mt-6">
            <VirusTotalCard data={moduleResult} />
          </div>
        )
      case 'standalone_port_scanner':
      case 'port_scan':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Active TCP Service Ports</h4>
            <PortsSection data={moduleResult} />
          </div>
        )
      case 'subdomains':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Discovered Host Subdomains</h4>
            <SubdomainsSection
              data={moduleResult}
              searchQuery={subQuery}
              setSearchQuery={setSubQuery}
              filter={subFilter}
              setFilter={setSubFilter}
            />
          </div>
        )
      case 'directories':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Discovered Directory Paths</h4>
            <DirectoriesSection
              data={moduleResult}
              filter={dirFilter}
              setFilter={setDirFilter}
            />
          </div>
        )
      case 'reverse_dns':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Reverse DNS Pointer PTR</h4>
            <ReverseDnsSection data={moduleResult} />
          </div>
        )
      case 'cloud_provider':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Cloud Infrastructure Provider</h4>
            <CloudProviderSection data={moduleResult} />
          </div>
        )
      case 'waf_detect':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">WAF Firewall Analysis</h4>
            <WafDetectionSection data={moduleResult} />
          </div>
        )
      case 'cms_fingerprint':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">CMS Platform Identification</h4>
            <CmsFingerprintSection data={moduleResult} />
          </div>
        )
      case 'http_availability':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">HTTP/HTTPS Accessibility</h4>
            {moduleResult?.checked_via_raw_ip && (
              <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 mb-4">
                <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-amber-800 font-semibold leading-relaxed">
                  {moduleResult.ip_sni_note}
                </p>
              </div>
            )}
            <HttpAvailabilitySection data={moduleResult} />
          </div>
        )
      case 'email_gather':
        return <EmailGatherSection data={moduleResult} />
      case 'shodan_intel':
        return (
          <div className="border border-slate-200 bg-white rounded-2xl p-6 shadow-sm mt-6">
            <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-4 border-b border-slate-100 pb-2">Shodan Intel (InternetDB)</h4>
            <ShodanSection data={moduleResult} />
          </div>
        )

      default:
        return null
    }
  }

  const renderWidget = () => {
    if (isBatch) {
      return (
        <div className="space-y-8">
          {scanData.results.map((targetData, idx) => (
            <div key={idx} className="border-b border-slate-250 border-slate-200 pb-8 last:border-0 last:pb-0">
              <div className="px-4 py-3 bg-slate-100 rounded-xl mb-4 text-xs font-extrabold text-slate-800 uppercase tracking-widest inline-block shadow-sm">
                Target: {targetData.target}
              </div>
              {renderSingleWidget(targetData.target, targetData.results?.[moduleKey], targetData.error)}
            </div>
          ))}
        </div>
      )
    } else {
      const targetName = scanData?.target || inputVal
      const r = scanData?.results || {}
      const moduleResult = r[moduleKey]
      return (
        <div>
          {targetName && (
            <div className="px-4 py-3 bg-slate-100 rounded-xl mb-4 text-xs font-extrabold text-slate-800 uppercase tracking-widest inline-block shadow-sm">
              Target: {targetName}
            </div>
          )}
          {renderSingleWidget(targetName, moduleResult, scanData?.error)}
        </div>
      )
    }
  }

  return (
    <div className="w-full animate-fade-in font-semibold">
      <button
        onClick={onBack}
        className="flex items-center gap-2 px-5 py-3 text-xs font-extrabold uppercase tracking-widest text-slate-700 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 hover:border-slate-300 hover:text-slate-900 shadow-sm hover:shadow transition-all duration-150 mb-8 cursor-pointer select-none"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Hub
      </button>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-3xl p-8 shadow-sm flex flex-col justify-between self-stretch">
          <div>
            <div className={`w-14 h-14 rounded-2xl border flex items-center justify-center mb-6 shadow-sm ${meta.color}`}>
              <Icon className="w-7 h-7" />
            </div>
            
            <h2 className="text-2xl font-black tracking-tight text-slate-900 leading-tight mb-3">
              {meta.title}
            </h2>
            
            <p className="text-sm text-stone-600 leading-relaxed font-semibold mb-6">
              {meta.desc}
            </p>

            <div className="border-t border-slate-100 pt-6">
              <h3 className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-4">
                What this check includes:
              </h3>
              <ul className="space-y-3 mb-6">
                {meta.details.map((d, index) => (
                  <li key={index} className="flex items-start gap-2 text-sm font-semibold text-slate-700 leading-normal">
                    <span className="w-1.5 h-1.5 rounded-full bg-teal-500/80 mt-1.5 flex-shrink-0" />
                    <span>{d}</span>
                  </li>
                ))}
              </ul>

              {meta.howItChecked && (
                <div className="border-t border-slate-100 pt-6">
                  <h3 className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-4">
                    How it is checked:
                  </h3>
                  <p className="text-sm text-slate-700 leading-relaxed font-semibold">
                    {meta.howItChecked}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-7 space-y-6">
          <div className="bg-white border border-slate-200 rounded-3xl p-8 shadow-sm">
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4">
              Single Check Configuration
            </h3>
            
            <form onSubmit={handleScan} className="space-y-4">
              {isBatchCapable ? (
                <div className="space-y-3">
                  <textarea
                    rows={4}
                    placeholder={
                      moduleKey === 'whois'
                        ? 'Up to 20 domains — comma-separated (e.g. google.com, wikipedia.org)'
                        : moduleKey === 'reverse_dns'
                        ? 'Up to 20 IP addresses — comma-separated, or a range like 110.0.0.1-20 (e.g. 8.8.8.8, 1.1.1.1)'
                        : 'Up to 20 IPs/domains — comma-separated, or a range like 110.0.0.1-20'
                    }
                    value={inputVal}
                    onChange={(e) => {
                      setInputVal(e.target.value)
                      setKeyError('')
                    }}
                    disabled={status === 'scanning'}
                    className="w-full px-5 py-4 border border-slate-350 border-slate-300 rounded-2xl text-xs font-normal leading-relaxed focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500 transition duration-150 shadow-inner bg-slate-50/50 resize-y"
                  />

                  {privateIpViolation && (
                    <p className="text-[10px] font-extrabold uppercase tracking-wide text-red-500">
                      '{privateIpViolation.target}' is a {privateIpViolation.reason}, not a public IP — this check only applies to public internet targets. Remove it to continue.
                    </p>
                  )}

                  {!privateIpViolation && malformedIpViolation && (
                    <p className="text-[10px] font-extrabold uppercase tracking-wide text-red-500">
                      '{malformedIpViolation.target}' is {malformedIpViolation.reason}. Fix or remove it to continue.
                    </p>
                  )}

                  {!privateIpViolation && !malformedIpViolation && (inputVal.includes(',') || RANGE_SHORT_RE.test(inputVal.trim()) || RANGE_FULL_RE.test(inputVal.trim())) && (() => {
                    let count = 0
                    let rawCount = 0
                    let rangeError = null
                    try {
                      count = parseTargetList(inputVal).length
                      rawCount = countRawExpandedTargets(inputVal)
                    } catch (rangeErr) {
                      rangeError = rangeErr.message
                    }
                    const overLimit = count > MAX_BATCH_TARGETS
                    const duplicatesRemoved = rawCount - count
                    let etaText = ''
                    if (count > 1 && !overLimit) {
                      if (moduleKey === 'virustotal') {
                        const etaSeconds = Math.round((count - 1) * 16)
                        const mins = Math.floor(etaSeconds / 60)
                        const secs = etaSeconds % 60
                        etaText = ` — est. ${mins > 0 ? `${mins}m ` : ''}${secs}s (VirusTotal allows ~4 checks/min)`
                      } else if (moduleKey === 'whois') {
                        const etaSeconds = Math.round((count - 1) * 2)
                        etaText = ` — est. ${etaSeconds}s (paced to avoid registry rate-limiting)`
                      }
                    }
                    const countText = duplicatesRemoved > 0
                      ? `${rawCount} entered, ${duplicatesRemoved} duplicate${duplicatesRemoved === 1 ? '' : 's'} removed — ${count} unique target${count === 1 ? '' : 's'}`
                      : `${count} target${count === 1 ? '' : 's'} detected`
                    return (
                      <p className={`text-[10px] font-extrabold uppercase tracking-wide ${(overLimit || rangeError) ? 'text-red-500' : 'text-slate-400'}`}>
                        {rangeError
                          ? rangeError
                          : `${countText}${overLimit ? ` — maximum is ${MAX_BATCH_TARGETS}` : ''}${etaText}`}
                      </p>
                    )
                  })()}

                  <button
                    type="submit"
                    disabled={!inputVal.trim() || status === 'scanning' || !!privateIpViolation || !!domainOnlyViolation || !!ipOnlyViolation || !!malformedIpViolation}
                    className={`w-full py-3.5 text-xs font-bold text-white uppercase tracking-wider rounded-2xl transition duration-150 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 ${meta.btnStyle}`}
                  >
                    <Play className="w-3.5 h-3.5" fill="currentColor" />
                    Scan {meta.title}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setInputVal('')
                      onReset()
                    }}
                    className={`w-full py-3.5 text-xs font-bold text-white uppercase tracking-wider rounded-2xl transition duration-150 flex items-center justify-center ${meta.btnStyle}`}
                  >
                    New Scan
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <input
                      type="text"
                      placeholder={['standalone_port_scanner', 'port_scan'].includes(moduleKey) ? "Enter Target IP or Domain (e.g. 1.1.1.1 or google.com)" : "Enter Target Host (e.g. google.in)"}
                      value={inputVal}
                      onChange={(e) => {
                        setInputVal(e.target.value)
                        setKeyError('')
                      }}
                      disabled={status === 'scanning'}
                      className="w-3/4 px-5 py-4 border border-slate-350 border-slate-300 rounded-2xl text-xs font-normal focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500 transition duration-150 shadow-inner bg-slate-50/50"
                    />
                    <button
                      type="submit"
                      disabled={!inputVal.trim() || status === 'scanning' || !!privateIpViolation || !!domainOnlyViolation || !!ipOnlyViolation || !!malformedIpViolation}
                      className={`w-1/4 py-4 text-xs font-bold text-white uppercase tracking-wider rounded-2xl transition duration-150 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-1.5 ${meta.btnStyle}`}
                    >
                      <Play className="w-3.5 h-3.5" fill="currentColor" />
                      Scan
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setInputVal('')
                      onReset()
                    }}
                    className={`w-full py-3.5 text-xs font-bold text-white uppercase tracking-wider rounded-2xl transition duration-150 flex items-center justify-center ${meta.btnStyle}`}
                  >
                    New Scan
                  </button>
                </div>
              )}

              {domainOnlyViolation && (
                <p className="text-red-500 text-[10px] font-extrabold tracking-wide uppercase -mt-2">
                  '{domainOnlyViolation.target}' is an IP address — this check requires a domain name. Remove it to continue.
                </p>
              )}

              {!domainOnlyViolation && ipOnlyViolation && (
                <p className="text-red-500 text-[10px] font-extrabold tracking-wide uppercase -mt-2">
                  '{ipOnlyViolation.target}' is a domain — this check requires an IP address. Remove it to continue.
                </p>
              )}

              {!domainOnlyViolation && !ipOnlyViolation && malformedIpViolation && (
                <p className="text-red-500 text-[10px] font-extrabold tracking-wide uppercase -mt-2">
                  '{malformedIpViolation.target}' is {malformedIpViolation.reason}. Fix it to continue.
                </p>
              )}

              {['abuseipdb', 'virustotal'].includes(moduleKey) && (
                <div className="space-y-2">
                  <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500 block">
                    {moduleKey === 'abuseipdb' ? 'AbuseIPDB API Key' : 'VirusTotal API Key'}
                  </label>
                  <input
                    type="password"
                    placeholder={`Enter your ${moduleKey === 'abuseipdb' ? 'AbuseIPDB' : 'VirusTotal'} API Key`}
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value)
                      setKeyError('')
                    }}
                    disabled={status === 'scanning'}
                    className="w-full px-5 py-4 border border-slate-350 border-slate-300 rounded-2xl text-xs font-normal focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500 transition duration-150 shadow-inner bg-slate-50/50"
                  />
                  {keyError && (
                    <p className="text-red-500 text-[10px] font-extrabold tracking-wide uppercase mt-1">
                      {keyError}
                    </p>
                  )}
                </div>
              )}

              {['standalone_port_scanner', 'port_scan'].includes(moduleKey) && (
                <div className="space-y-2 pt-1">
                  <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500 block">
                    Select Port Range Column
                  </label>
                  <select
                    value={portRange}
                    onChange={(e) => setPortRange(e.target.value)}
                    disabled={status === 'scanning'}
                    className="w-full px-5 py-4 border border-slate-300 rounded-2xl text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500 transition duration-150 shadow-inner bg-slate-50/50 text-slate-900 cursor-pointer"
                  >
                    <option value="top100">Top 100 Ports (Top 100 Most Important Ports)</option>
                    <option value="1-1024">1 - 1024 Ports (System Well-Known Ports)</option>
                    <option value="1-65535">1 - 65535 Ports (Full Range Scan)</option>
                  </select>
                </div>
              )}
            </form>
          </div>

          {status === 'scanning' && (
            <div className="border border-slate-200 bg-white rounded-3xl p-10 shadow-sm flex flex-col items-center justify-center text-center">
              <Loader2 className="w-8 h-8 text-orange-500 animate-spin mb-4" />
              <div className="text-xs font-bold uppercase tracking-widest text-slate-700 mb-1">
                Running separate query
              </div>
              <div className="text-[10px] text-slate-400 font-bold mb-4">
                Fetching only {meta.title} variables...
              </div>
              {scanningTargets.length > 0 && (
                <div className="w-full max-w-md">
                  <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-400 mb-2">
                    {scanningTargets.length > 1 ? `Checking ${scanningTargets.length} targets` : 'Checking'}
                  </div>
                  <div className="flex flex-wrap gap-1.5 justify-center max-h-32 overflow-y-auto px-2">
                    {scanningTargets.map((t, i) => (
                      <span
                        key={i}
                        className="mono text-[10px] font-bold text-slate-600 bg-slate-100 border border-slate-200 rounded-lg px-2.5 py-1"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {status === 'error' && error && (
            <div className="border border-red-200 bg-white rounded-3xl p-6 shadow-sm glow-red">
              <div className="font-bold text-red-600 text-xs uppercase tracking-wider mb-3">
                Scan Execution Failed
              </div>
              <div className="text-xs font-mono bg-stone-50 border border-stone-200 rounded-lg p-4 text-stone-600 break-all leading-relaxed">
                {error}
              </div>
            </div>
          )}

          {status === 'done' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3 mb-2">
                <span className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400">
                  Scan Output Findings
                </span>
                <button
                  onClick={downloadIndividualReport}
                  className="flex items-center gap-1.5 px-3 py-1.5 border border-teal-200 hover:border-teal-350 bg-teal-50 hover:bg-teal-100 text-teal-700 font-extrabold uppercase tracking-widest text-[9px] rounded-xl transition duration-150 cursor-pointer shadow-sm animate-fade-in"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download Report
                </button>
              </div>
              {renderWidget()}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}




