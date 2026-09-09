# Reconnaissance & Security Audit Scanner

A comprehensive web reconnaissance and security assessment tool built with Python (FastAPI) backend and React frontend. This tool performs passive OSINT, active network scanning, and threat intelligence checks on target domains and IP addresses.

---

## Table of Contents

1. [Overview](#overview)
2. [Technology Stack](#technology-stack)
3. [Project Directory Structure](#project-directory-structure)
4. [Application Flow](#application-flow)
5. [Frontend-Backend Communication](#frontend-backend-communication)
6. [Module Details](#module-details)
7. [Setup & Execution](#setup--execution)
8. [Scan Modes & Optimization](#scan-modes--optimization)
9. [Batch Scanning](#batch-scanning)
10. [API Reference](#api-reference)

---

## Overview

The tool allows users to scan target domains or IP addresses and receive comprehensive security information. It operates in two scan modes:

- **Standard Mode**: Quick scan (15-30 seconds) with DNS, WHOIS, SSL, GeoIP, headers, web tech, reputation, subdomains
- **Deep Mode**: Comprehensive scan (2-3 minutes) includes Standard checks plus port scanning (top 1000) and directory enumeration

Results are displayed in organized tabs and can be exported as standalone HTML reports. The tool supports batch subdomain scanning with background processing and real-time progress updates.

---

## Technology Stack

### Backend (Python 3.12+)

| Component | Purpose | Key Features |
|---|---|---|
| **FastAPI** | Web framework | Async request handling, automatic OpenAPI docs |
| **Uvicorn** | ASGI server | Runs backend on port 8000 |
| **Asyncio** | Concurrency | Runs 300+ concurrent tasks (DNS, HTTP, sockets) |
| **Aiohttp** | Async HTTP client | Non-blocking API queries and web requests |
| **Dnspython** | DNS queries | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records |
| **Python-Whois** | WHOIS/RDAP | Domain registration data, expiry dates |
| **SSL (built-in)** | TLS handshakes | Certificate extraction, protocol enumeration |
| **Socket (built-in)** | Network I/O | Port scanning, reverse DNS |
| **SQLite3** | Database | User accounts, scan history, API keys |
| **JWT (PyJWT)** | Authentication | Token-based auth, 30-min session timeout |
| **Subprocess** | CLI tools | Runs theHarvester for email harvesting |

### Frontend (Node.js 18+)

| Component | Purpose | Key Features |
|---|---|---|
| **React 18** | UI framework | Component-based, hooks, state management |
| **Vite** | Build tool | Dev server on port 5173, HMR, fast bundling |
| **React Router** | Navigation | Client-side routing between pages |
| **Context API** | State management | BackgroundScansContext, NotificationsContext |
| **Tailwind CSS** | Styling | Utility-first, custom color schemes |
| **Lucide React** | Icons | 50+ icons for UI elements |
| **Fetch API** | HTTP client | JSON requests to backend |

---

## Project Directory Structure

```
recon-tool/
├── README.md                          # Documentation (this file)
├── .gitignore                         # Git ignore patterns
│
├── backend/                           # Python FastAPI backend
│   ├── main.py                        # Main entry point - Route handlers
│   ├── auth.py                        # JWT token generation, password hashing
│   ├── auth_router.py                 # /auth endpoints (register, login, validate)
│   ├── database.py                    # SQLite connection, CRUD operations
│   ├── models.py                      # Pydantic data models
│   ├── batch_scanner.py               # Batch subdomain scanning logic
│   ├── requirements.txt               # Python dependencies
│   ├── .env.example                   # Template for API keys
│   ├── .env                           # Configuration (DO NOT commit)
│   ├── users.db                       # SQLite database (auto-created)
│   │
│   ├── modules/                       # 16 specialized scanning modules
│   │   ├── dns_recon.py               # DNS records + reverse PTR
│   │   ├── whois_lookup.py            # WHOIS/RDAP queries + expiry calc
│   │   ├── ssl_check.py               # TLS handshake, cert extraction
│   │   ├── geo_ip.py                  # GeoIP location lookup (3 APIs)
│   │   ├── http_headers.py            # HTTP headers + security audit
│   │   ├── web_tech.py                # Web server, framework, CDN detection
│   │   ├── port_scanner.py            # TCP port scanning (100/1000 ports)
│   │   ├── subdomain_finder.py        # Passive OSINT + DNS brute-force
│   │   ├── directory_enum.py          # Path fuzzing (200+ endpoints)
│   │   ├── cloud_provider.py          # AWS, GCP, Azure, Cloudflare detection
│   │   ├── waf_detect.py              # WAF fingerprinting (25+ vendors)
│   │   ├── cms_fingerprint.py         # WordPress, Shopify, Joomla detection
│   │   ├── cors_check.py              # CORS + open redirect testing
│   │   ├── email_gather.py            # Email harvesting via theHarvester
│   │   └── reputation.py              # AbuseIPDB + VirusTotal queries
│   │
│   └── utils/                         # Shared utilities
│       ├── helpers.py                 # Input validation, DNS resolution
│       └── safety.py                  # Timeout wrappers, error handling
│
└── frontend/                          # React + Vite frontend
    ├── package.json                   # Node.js config, dependencies
    ├── package-lock.json              # Locked dependency versions
    ├── vite.config.js                 # Dev server, API proxy config
    ├── tailwind.config.js             # Custom Tailwind configuration
    ├── postcss.config.js              # PostCSS plugins
    ├── index.html                     # HTML entrypoint
    │
    └── src/
        ├── main.jsx                   # React root bootstrap
        ├── App.jsx                    # Root component, state management
        ├── styles.css                 # Global styles, animations
        │
        ├── components/                # Reusable UI components
        │   ├── ScanForm.jsx           # Input form (domain/IP, mode select)
        │   ├── ScanProgress.jsx       # Live progress tracking
        │   ├── Results.jsx            # Tabbed results display
        │   ├── BatchScanProgress.jsx  # Batch scan progress bar
        │   ├── BatchScanResults.jsx   # Batch results grid
        │   ├── ScanHistoryModal.jsx   # Historical scan list
        │   ├── StartBatchScanModal.jsx# Batch config dialog
        │   ├── NotificationBell.jsx   # Notification center
        │   ├── BackgroundScansWidget.jsx # Floating progress widget
        │   ├── UserHeaderMenu.jsx     # Account menu
        │   ├── BackgroundScansContext.jsx # Global scan state
        │   └── NotificationsContext.jsx # Global notification state
        │
        └── utils/
            └── scanReportHtml.js      # HTML report generation
```

---

## Application Flow

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│                    (Port 5173 - Frontend)                        │
│                                                                   │
│  • ScanForm → Get domain/IP input                               │
│  • ScanProgress → Show real-time status                         │
│  • Results → Display findings in tabs                           │
│  • BackgroundScansWidget → Track batch scans                    │
│  • NotificationBell → Show events                               │
└────────────────────────────┬──────────────────────────────────┘
                             │
                             │ HTTP JSON Requests
                             │ (fetch API)
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                    FASTAPI BACKEND                               │
│                  (Port 8000 - Backend)                           │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ API Routes (main.py)                                     │   │
│  │ • POST /scan → Single scan                              │   │
│  │ • POST /scan/batch → Batch scanning                     │   │
│  │ • GET /history/scans → Scan history                     │   │
│  │ • POST /auth/register → User registration               │   │
│  │ • POST /auth/login → Login                              │   │
│  │ • GET /scan/{id}/results → Full results                 │   │
│  │ • GET /scan/batch-results/{id} → Batch results          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Async Task Orchestration (main.py)                       │   │
│  │ • Input validation                                       │   │
│  │ • DNS resolution                                         │   │
│  │ • Wave 1: 13 lightweight modules (concurrent)            │   │
│  │ • Wave 2: 2 heavy modules (if deep scan)                 │   │
│  │ • Error handling & timeouts                              │   │
│  │ • Result aggregation & sanitization                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 16 Scanning Modules (backend/modules/)                   │   │
│  │ • Each module: Input → Process → Output JSON             │   │
│  │ • Concurrent execution via asyncio                       │   │
│  │ • Individual timeout per module                          │   │
│  │ • Error handling (return {"status": "error"})            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ External Data Sources                                    │   │
│  │ • crt.sh - Certificate Transparency logs                 │   │
│  │ • HackerTarget - OSINT database                          │   │
│  │ • Shodan - Reverse IP lookup                             │   │
│  │ • AbuseIPDB - IP reputation (rate: 1 req/0.1s)           │   │
│  │ • VirusTotal - Malware detection (rate: 1 req/16s)       │   │
│  │ • ip-api.com, freeipapi.com, ipinfo.io - GeoIP           │   │
│  │ • AWS/GCP/Azure/Cloudflare IP ranges                     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ SQLite Database (users.db)                               │   │
│  │ • User accounts + auth tokens                            │   │
│  │ • Scan history + full results JSON                       │   │
│  │ • Batch scan progress                                    │   │
│  │ • API keys (encrypted)                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Application Flow

**1. User Accesses Application**
```
→ Browser opens http://localhost:5173
→ React App.jsx loads
→ Checks localStorage for auth token
→ If valid: shows ScanForm
→ If expired: redirects to login
```

**2. User Enters Scan Details**
```
→ ScanForm.jsx collects:
  • Target: domain or IP
  • Mode: standard or deep
  • Optional: API keys for reputation checks
→ Validates input (domain/IP format)
→ Sets state: status = 'scanning'
→ Displays ScanProgress.jsx (real-time timer)
```

**3. Frontend Makes API Request**
```
→ fetch('http://localhost:8000/scan', {
    method: 'POST',
    body: JSON.stringify({
      target: 'example.com',
      mode: 'standard',
      include_reputation: true
    })
  })
→ Vite dev server proxies /api → http://localhost:8000
```

**4. Backend Receives Request**
```
→ FastAPI route handler validates input
→ Calls is_valid_input() in helpers.py
→ Resolves domain to IP via DNS
→ Creates scan record in database
→ Returns scan_id to frontend (for progress tracking)
```

**5. Backend Orchestrates Scanning**
```
→ Runs Wave 1: 13 concurrent modules
  • All run at the same time (asyncio.gather)
  • Each wrapped in timeout handler (5-20 seconds)
  • If one times out, others continue
  
→ If Deep mode: runs Wave 2 after Wave 1 completes
  • Port scanner (top 1000 ports, 180 seconds)
  • Directory enumeration (200+ paths, 180 seconds)
```

**6. Results Aggregation**
```
→ Combines Wave 1 + Wave 2 results
→ Sanitizes data (removes invalid characters)
→ Wraps in response schema:
  {
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "scan_duration_seconds": 42.5,
    "results": { all module data }
  }
→ Saves to database
→ Returns to frontend
```

**7. Frontend Displays Results**
```
→ Receives JSON response
→ Updates state: status = 'done', scanData = response
→ Switches component: ScanProgress → Results
→ Renders 6 tabs:
  • Overview (risk summary)
  • Network (ports, GeoIP)
  • Domain (WHOIS, DNS)
  • Web (headers, cookies, tech)
  • Recon (subdomains, directories)
  • Threat (reputation scores)
```

**8. User Actions**
```
→ Can export as HTML report
→ Can view scan history
→ Can start new scan
→ Can start batch scan
→ Can logout (clears token)
```

---

## Frontend-Backend Communication

### Request/Response Flow

**All API calls use JSON over HTTP:**

#### Example 1: Single Domain Scan

**Frontend Request** (`POST /scan`):
```json
{
  "target": "example.com",
  "mode": "standard",
  "include_reputation": true,
  "abuseipdb_key": "...",
  "virustotal_key": "..."
}
```

**Backend Response** (`200 OK`):
```json
{
  "scan_id": "uuid-123",
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "is_domain": true,
  "scan_mode": "standard",
  "scan_duration_seconds": 23.45,
  "scanned_at": "2026-08-06T14:30:00Z",
  "module_summary": {
    "ok": ["dns_records", "whois", "ssl_certificate", ...],
    "timeout": [],
    "error": []
  },
  "results": {
    "dns_records": { ... },
    "whois": { ... },
    "ssl_certificate": { ... },
    "geo_ip": { ... },
    "http_headers": { ... },
    "web_tech": { ... },
    "port_scanner": { ... },
    "subdomain_finder": { ... }
  }
}
```

#### Example 2: Batch Subdomain Scan

**Frontend Request** (`POST /scan/batch`):
```json
{
  "domain": "example.com",
  "subdomains": ["www", "api", "mail", "staging", ...],
  "max_parallel": 10,
  "api_keys": {
    "abuseipdb": "...",
    "virustotal": "..."
  }
}
```

**Backend Response** (`200 OK`):
```json
{
  "batch_id": "uuid-456",
  "domain": "example.com",
  "total_subdomains": 50,
  "status": "running",
  "created_at": "2026-08-06T14:30:00Z"
}
```

**Frontend Progress Polling** (`GET /scan/batch/{batch_id}/progress`):
- Polls every 1 second
- Gets updated progress

**Response**:
```json
{
  "batch_id": "uuid-456",
  "status": "running",
  "total": 50,
  "completed": 23,
  "progress_percent": 46,
  "failed": 0
}
```

**After Completion** (`GET /scan/batch-results/{batch_id}`):
```json
{
  "batch_id": "uuid-456",
  "domain": "example.com",
  "total_subdomains": 50,
  "completed_scans": 50,
  "failed_scans": 0,
  "results": [
    {
      "subdomain": "www.example.com",
      "resolved_ips": ["93.184.216.34"],
      "status": "completed",
      "scan_result": { full module results }
    },
    ...
  ]
}
```

### API Endpoints Summary

| Method | Endpoint | Purpose | Auth Required |
|---|---|---|---|
| POST | /scan | Single domain/IP scan | Yes |
| POST | /scan/batch | Start batch subdomain scan | Yes |
| GET | /scan/batch/{id}/progress | Get batch progress | Yes |
| GET | /scan/batch-results/{id} | Get batch results | Yes |
| GET | /scan/{id}/results | Get single scan results | Yes |
| GET | /history/scans | Get user's scan history | Yes |
| POST | /auth/register | Register new user | No |
| POST | /auth/login | User login | No |
| POST | /auth/validate | Validate token | Yes |

---

## Module Details - Complete Learning Guide

Each module is a specialized scanning engine. This section provides comprehensive information about each module's mechanics, implementation details, and how to interpret results.

---

### 1. DNS Records Reconnaissance (`dns_recon.py`)

**Purpose**: Maps domain's DNS infrastructure - finds mail servers, nameservers, aliases, and other DNS records.

**Files**: `backend/modules/dns_recon.py`

**Libraries Used**:
- `dnspython` (Python DNS toolkit) - Primary DNS resolution
- `socket` (Python built-in) - Fallback reverse DNS, system resolver
- `subprocess` (Python built-in) - Fallback to nslookup command on Windows

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (5 seconds)

**What It Checks** (8 DNS record types):

| Record Type | What It Means | Security Relevance | Example |
|---|---|---|---|
| **A** | IPv4 address | Points to main server | `93.184.216.34` |
| **AAAA** | IPv6 address | IPv6 server address | `2606:2800:220:1:248:1893:25c8:1946` |
| **MX** | Mail servers | Where emails are routed | Priority 10: mail.example.com |
| **NS** | Nameservers | Which servers handle DNS | ns1.example.com, ns2.example.com |
| **TXT** | Text records | SPF, DKIM, DMARC (email auth) | `v=spf1 include:_spf.google.com ~all` |
| **CNAME** | Aliases | Domain aliases | www → example.com |
| **SOA** | Start of Authority | Zone admin, serial, refresh | Contains TTL, retry info |
| **CAA** | Certificate Authority | Who can issue SSL certs | CA: letsencrypt.org |

**How It Works**:

```
Step 1: Try system DNS resolver
  ↓ (if timeout/fail)
Step 2: Query Google DNS (8.8.8.8) and Cloudflare (1.1.1.1)
  ↓ (if still fails)
Step 3: Fallback to socket.gethostbyname() or nslookup command
```

**Implementation Details**:

```python
# Primary query method
resolver = dns.resolver.Resolver()
answers = await resolver.resolve(domain, 'A')  # Async DNS query

# Fallback resolvers
resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google, Cloudflare

# Timeout handling
resolver.lifetime = 5.0  # Total time for retries
resolver.timeout = 2.5   # Per-query timeout
```

**Common Issues & Solutions**:

| Issue | Cause | Solution |
|---|---|---|
| **All records return empty** | Domain doesn't exist or DNS down | Check domain spelling, try another nameserver |
| **Only A record found** | Domain has minimal DNS setup | Normal for simple setups, check if MX is needed |
| **Timeout on A records** | DNS server slow or blocked | Backend retries with Google/Cloudflare DNS |
| **MX record missing** | No mail server configured | Domain doesn't receive emails |
| **SPF record broken** | Malformed TXT record | Email might fail spam checks |

**Security Insights** (What You Learn From Results):

1. **Multiple A records** → Load balanced (multiple servers)
2. **No AAAA record** → No IPv6 support
3. **SPF/DKIM/DMARC missing** → Email vulnerable to spoofing
4. **NS records pointing to domain registrar** → Using registrar's DNS (common)
5. **CAA with restrictive CAs** → Better security (limits who can issue certs)
6. **CNAME instead of A record** → Using CDN or external host

**Output Structure**:

```json
{
  "status": "ok",  // or "timeout", "error"
  "records_by_type": {
    "A": {
      "status": "ok",
      "records": ["93.184.216.34"]
    },
    "AAAA": {
      "status": "ok",
      "records": ["2606:2800:220:1:248:1893:25c8:1946"]
    },
    "MX": {
      "status": "ok",
      "records": [
        {
          "priority": 10,
          "exchange": "mail.example.com"
        }
      ]
    },
    "NS": {
      "status": "ok",
      "records": ["ns1.example.com", "ns2.example.com"]
    },
    "TXT": {
      "status": "ok",
      "records": [
        "v=spf1 include:_spf.google.com ~all",
        "v=DMARC1; p=quarantine;"
      ]
    },
    "SOA": {
      "status": "ok",
      "mname": "ns1.example.com",
      "rname": "admin.example.com",
      "serial": 2024010101,
      "refresh": 3600,
      "retry": 1800,
      "expire": 604800,
      "minimum_ttl": 3600
    },
    "CNAME": {
      "status": "ok",
      "records": ["www.example.com"]
    },
    "CAA": {
      "status": "ok",
      "records": [
        {
          "flags": 0,
          "tag": "issue",
          "value": "letsencrypt.org"
        }
      ]
    }
  },
  "reverse_dns": {
    "status": "ok",
    "hostname": "example.com"
  }
}
```

**Real-World Example - Google.com**:

```
A: 142.250.185.46
AAAA: 2607:f8b0:4004:80c::200e
MX: 10 smtp.google.com, 20 smtp2.google.com
NS: ns1.google.com, ns2.google.com, ns3.google.com, ns4.google.com
TXT: Multiple SPF/DMARC records
CAA: letsencrypt.org, google.com (only these CAs can issue certs)
SOA: ns1.google.com (primary), hostmaster@google.com (admin)
```

**Why This Matters for Security**:
- Shows if domain has redundancy (multiple MX = email won't go down if one fails)
- Reveals email authentication setup (SPF/DKIM/DMARC = harder to spoof)
- Shows who can issue SSL certs (CAA = prevents unauthorized certs)
- Identifies infrastructure setup (load balancing, CDN usage)

---

### 2. WHOIS Lookup & Expiry Tracking (`whois_lookup.py`)

**Purpose**: Retrieves domain registration information and calculates expiration dates.

**Files**: `backend/modules/whois_lookup.py`

**Libraries Used**:
- `python-whois` - WHOIS protocol (port 43 TCP)
- `aiohttp` - RDAP API queries (HTTP fallback)
- `datetime` - Date calculations

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (5 seconds)

**How It Works**:

```
Method 1: WHOIS Query (port 43)
  • Connect to whois.verisign-grs.com (for .com domains)
  • Send: "domain example.com\r\n"
  • Parse text response for key fields
  
Method 2: RDAP API (if WHOIS blocked/slow)
  • Query: GET /domain/example.com to rdap.org
  • Returns structured JSON
  • More modern, rate-limit friendly
```

**What It Finds**:

| Field | What It Is | Security Relevance | Example |
|---|---|---|---|
| **Registrar** | Company managing the domain | Tells you who to contact for issues | GoDaddy, Namecheap, AWS |
| **Registration Date** | When domain was registered | Indicates how old the domain is | 2015-08-14 |
| **Expiration Date** | When domain registration expires | Critical alert if expiring soon | 2025-08-13 |
| **Registrant** | Person/company that owns domain | WHOIS privacy affects visibility | Name, email, address |
| **Nameservers** | DNS servers for domain | Which servers handle DNS queries | ns1.example.com |
| **Status** | Domain registration status | Should be "ok" or "active" | clientTransferProhibited |

**Expiration Logic**:

```python
registration_date = parse_date("2015-08-14")
expiration_date = parse_date("2025-08-13")
days_remaining = (expiration_date - datetime.now()).days

# Status determination
if days_remaining < 0:
    status = "EXPIRED"  # ⚠️ Alert! Domain no longer owned
elif days_remaining < 30:
    status = "EXPIRING_SOON"  # ⚠️ Warning! Will expire soon
else:
    status = "VALID"  # ✓ OK, plenty of time left
```

**Common Issues & How Tool Handles Them**:

| Issue | How Tool Handles | What You Should Do |
|---|---|---|
| **WHOIS blocked** | Falls back to RDAP API | Tool continues, gets data from RDAP |
| **WHOIS privacy enabled** | Shows "Privacy Protected" | Can't identify owner, but that's intentional |
| **Domain recently registered** | Shows recent date | Normal, watch expiration |
| **Domain near expiration** | Flags as "EXPIRING_SOON" | Renew immediately to avoid loss |
| **Invalid WHOIS response** | Returns error status | Might be fake domain or WHOIS issues |

**Output Structure**:

```json
{
  "status": "ok",
  "registrar": "VeriSign Global Registry Services",
  "registration_date": "1995-08-14T00:00:00Z",
  "expiration_date": "2025-08-13T00:00:00Z",
  "days_remaining": 378,
  "expiration_status": "valid",  // or "expiring_soon", "expired"
  "updated_date": "2024-08-01T00:00:00Z",
  "registrant": {
    "name": "Domain Owner Name",
    "organization": "Example Inc.",
    "email": "admin@example.com",
    "address": "123 Main St",
    "country": "US",
    "phone": "+1.5555555555",
    "privacy_protected": false
  },
  "nameservers": [
    "ns1.example.com",
    "ns2.example.com",
    "ns3.example.com",
    "ns4.example.com"
  ],
  "status_flags": [
    "clientTransferProhibited",
    "serverUpdateProhibited"
  ],
  "registrar_url": "https://example.com"
}
```

**Real-World Example - Google.com**:

```
Registrar: MarkMonitor Inc.
Registered: June 15, 1997
Expires: June 15, 2026 (1 year 10 months left)
Registrant: Google LLC
Status: Active
Nameservers: ns1.google.com through ns4.google.com
Transfer Status: clientTransferProhibited (locked, can't transfer)
```

**Security Insights**:

1. **Domain age** → Older domains = more established (less likely malicious)
2. **Recent registration** → New site, watch for scams
3. **Expiring soon** → Site owner might lose it → risk of hijack
4. **Privacy protected** → Owner wants anonymity (common for security)
5. **Transfer locked** → Good security practice
6. **Multiple nameservers** → Redundancy

---

### 3. SSL/TLS Certificate Analysis (`ssl_check.py`)

**Purpose**: Examines HTTPS certificates for validity, expiration, configuration.

**Files**: `backend/modules/ssl_check.py`

**Libraries Used**:
- `ssl` (Python built-in) - TLS connections and certificate parsing
- `socket` (Python built-in) - TCP connections
- `datetime` - Certificate date calculations

**Scan Modes**:
- Standard: ✓ Yes (12 seconds)
- Deep: ✓ Yes (12 seconds)
- Single Module: ✓ Yes (8 seconds)

**Connection Process**:

```python
# 1. Open TCP connection to port 443
sock = socket.create_connection((domain, 443), timeout=10)

# 2. Create SSL context
context = ssl.create_default_context()

# 3. Perform TLS handshake
with context.wrap_socket(sock, server_hostname=domain) as ssock:
    # 4. Extract certificate
    cert = ssock.getpeercert()
    cert_bin = ssock.getpeercert(binary_form=True)
```

**What It Extracts**:

| Field | What It Means | Security Relevance |
|---|---|---|
| **Common Name (CN)** | Primary domain on cert | Should match your domain |
| **Subject Alt Names (SAN)** | Other domains on cert | Can have multiple domains |
| **Issuer** | Certificate Authority | DigiCert, Let's Encrypt, etc. |
| **Valid From/Until** | Certificate dates | If expired = browser warnings |
| **Public Key Bits** | Key strength (2048, 4096) | 2048 = OK, 4096 = better |
| **Signature Algorithm** | Crypto method | sha256WithRSAEncryption (standard) |
| **Fingerprint** | Certificate hash | Used to identify cert uniquely |
| **TLS Versions** | Which TLS versions work | 1.2, 1.3 = good |

**Protocol Testing Logic**:

```python
# Test which TLS versions are supported
for protocol in ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
    try:
        context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol}'))
        # Try to connect with this protocol
        with context.wrap_socket(sock, server_hostname=domain):
            pass
        supported_protocols.append(protocol)  # Success!
    except:
        pass  # Not supported
```

**Error Handling** (User-Friendly Messages):

```python
# Instead of cryptic SSL errors, returns clear messages:

"Certificate has expired"
→ "SSL/TLS certificate expired on 2024-01-15. Renew immediately."

"Certificate does not match hostname"
→ "Certificate for *.example.com doesn't match example.org. Check certificate."

"Self-signed certificate"
→ "Certificate is self-signed (not verified by authority). Install on client or buy real cert."

"No certificate found"
→ "No HTTPS certificate. Server either doesn't support HTTPS or certificate not found."
```

**Certificate Chain Verification**:

```
Client Certificate Chain:
  1. Certificate for example.com (Issued by DigiCert)
  2. DigiCert Intermediate CA (Issued by DigiCert Root)
  3. DigiCert Root CA (Self-signed, trusted by browsers)
```

**Output Structure**:

```json
{
  "status": "ok",
  "certificate": {
    "common_name": "example.com",
    "subject_alternative_names": [
      "example.com",
      "www.example.com",
      "*.example.com"
    ],
    "issuer": {
      "organization": "DigiCert Inc",
      "organizational_unit": "www.digicert.com",
      "common_name": "DigiCert TLS RSA SHA256 2020 CA1"
    },
    "valid_from": "2023-11-01T00:00:00Z",
    "valid_until": "2025-11-30T23:59:59Z",
    "days_remaining": 478,
    "expiration_status": "valid",  // or "expiring_soon", "expired"
    "public_key": {
      "algorithm": "rsaEncryption",
      "bits": 2048
    },
    "signature_algorithm": "sha256WithRSAEncryption",
    "fingerprint": "SHA256:ABC123...",
    "serial_number": "05417C7A95B0DB8956..."
  },
  "tls_versions": {
    "TLSv1.0": false,  // Outdated, disabled
    "TLSv1.1": false,  // Outdated, disabled
    "TLSv1.2": true,   // Good
    "TLSv1.3": true    // Best
  },
  "cipher_suites": [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_AES_128_GCM_SHA256"
  ],
  "certificate_chain": [
    "example.com (Issued by DigiCert)",
    "DigiCert Intermediate CA",
    "DigiCert Root CA"
  ]
}
```

**Real-World Example - Google.com**:

```
CN: google.com
SANs: *.google.com, *.appspot.com, *.metrics.gstatic.com
Issuer: Google Trust Services (Google's own CA now)
Valid: Jan 1, 2024 to Jan 1, 2025
Key: 2048-bit RSA
TLS: 1.2 and 1.3 supported
Status: ✓ Valid, well-configured
```

**Security Assessment**:

| Finding | What It Means | Action |
|---|---|---|
| **TLS 1.2 + 1.3** | Good, modern | ✓ OK |
| **Only TLS 1.0** | Outdated, insecure | ⚠️ Should upgrade |
| **2048-bit key** | Standard | ✓ OK |
| **4096-bit key** | Stronger | ✓ Better |
| **Expired cert** | Browser warnings | ⚠️ Critical - renew now |
| **Expiring in 30 days** | Will expire soon | ⚠️ Renew soon |
| **Wildcard cert** | Covers all subdomains | ✓ Efficient |
| **Multiple SANs** | Multiple domains on one cert | ✓ Common, efficient |

---

### 4. GeoIP & Location Detection (`geo_ip.py`)

**Purpose**: Maps IP address to physical location and network information.

**Files**: `backend/modules/geo_ip.py`

**Libraries Used**:
- `aiohttp` - Async HTTP queries to 3 GeoIP APIs
- All queries run in parallel for speed

**Scan Modes**:
- Standard: ✓ Yes (8 seconds)
- Deep: ✓ Yes (8 seconds)
- Single Module: ✓ Yes (5 seconds)

**APIs Used** (Queried Concurrently):

```python
# All three queries run at the same time
tasks = [
    query_ip_api(ip),       # Primary source
    query_freeipapi(ip),    # Backup
    query_ipinfo(ip)        # Backup
]
results = await asyncio.gather(*tasks)

# Merge data: ip-api is primary, others fill gaps
```

| API | Speed | Accuracy | Coverage | Rate Limit |
|---|---|---|---|---|
| **ip-api.com** | Fast | High | Excellent | 45 req/min free |
| **freeipapi.com** | Medium | Good | Good | Generous |
| **ipinfo.io** | Fast | High | Excellent | 50k req/month free |

**Data Extracted**:

```
┌─ Geographic Data
│  ├─ Country (ISO code + name)
│  ├─ City
│  ├─ State/Province
│  ├─ Latitude, Longitude
│  └─ Timezone
│
├─ Network Data
│  ├─ ISP (Internet Service Provider)
│  ├─ ASN (Autonomous System Number)
│  ├─ Netblock
│  └─ Connection Type (residential, business, datacenter)
│
└─ Generated
   └─ Google Maps URL
```

**Connection Type Detection**:

```python
connection_types = {
    'residential': 'Home internet',
    'business': 'Business internet',
    'datacenter': 'Hosting provider',
    'vpn': 'VPN service',
    'proxy': 'Proxy server',
    'mobile': 'Cellular connection',
    'unknown': 'Cannot determine'
}
```

**Output Structure**:

```json
{
  "status": "ok",
  "ip": "93.184.216.34",
  "hostname": "example.com",
  "location": {
    "country": {
      "code": "US",
      "name": "United States"
    },
    "continent": "North America",
    "state": "Massachusetts",
    "city": "Los Angeles",
    "latitude": 34.0522,
    "longitude": -118.2437,
    "accuracy_radius_km": 1000
  },
  "network": {
    "isp": "ICANN (Internet Assigned Numbers Authority)",
    "organization": "Internet Assigned Numbers Authority",
    "asn": "AS12345",
    "netblock": "93.184.216.0/24",
    "connection_type": "datacenter",
    "mobile": false
  },
  "timezone": "America/Los_Angeles",
  "currency": "USD",
  "maps_url": "https://www.google.com/maps?q=34.0522,-118.2437"
}
```

**Real-World Example - Amazon AWS IP**:

```
IP: 52.1.2.3 (AWS)
Location: US, Virginia (AWS Virginia region)
ISP: Amazon.com Inc.
ASN: AS16509 Amazon Technologies
Connection Type: Datacenter
Accuracy: Unknown (AWS is geographically distributed)
```

**Security Insights**:

1. **Datacenter IP** → Hosting provider (might be site host)
2. **Residential IP** → Someone's home (suspicious if it's a company)
3. **VPN/Proxy** → Owner hiding location (could be legitimate or suspicious)
4. **Unexpected country** → Site on unexpected server (check if expected)
5. **Accuracy low** → GPS coordinates might be far off

---

### 5. HTTP Headers Security Audit (`http_headers.py`)

**Purpose**: Analyzes HTTP response headers to assess security configuration.

**Files**: `backend/modules/http_headers.py`

**Libraries Used**:
- `aiohttp` - HTTP requests with custom headers
- Header parsing (standard)

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (8 seconds)

**Request Process**:

```python
# 1. Try HTTPS first (secure)
try:
    resp = await session.get(f'https://{domain}/', 
                             allow_redirects=True, 
                             timeout=10)
except:
    # 2. Fallback to HTTP (insecure)
    resp = await session.get(f'http://{domain}/', 
                             allow_redirects=True, 
                             timeout=10)

# 3. Collect all response headers
headers = dict(resp.headers)
cookies = resp.cookies
```

**Critical Security Headers** (What They Do):

| Header | Purpose | Good Value | Bad Value |
|---|---|---|---|
| **HSTS** | Force HTTPS | `max-age=31536000; includeSubDomains` | Not present |
| **CSP** | Prevent XSS | `default-src 'self'` | `default-src *` (allows all) |
| **X-Frame-Options** | Prevent clickjacking | `DENY` or `SAMEORIGIN` | Not present |
| **X-Content-Type-Options** | Prevent MIME sniffing | `nosniff` | Not present |
| **Referrer-Policy** | Control referrer data | `strict-origin-when-cross-origin` | Not present |

**How Each Protects**:

```
HSTS: Prevents downgrade attacks
  Attack: Hacker intercepts, downgrades to HTTP
  Protection: Browser refuses HTTP, always uses HTTPS

CSP: Prevents inline script injection
  Attack: Hacker injects <script>steal data</script>
  Protection: Browser blocks inline scripts, only allows approved sources

X-Frame-Options: Prevents clickjacking
  Attack: Hacker embeds your site in invisible iframe, tricks users
  Protection: Browser refuses to load in iframe

X-Content-Type-Options: Prevents MIME sniffing
  Attack: Hacker uploads .txt with JavaScript, browser runs as .js
  Protection: Browser trusts Content-Type header, won't sniff

Referrer-Policy: Prevents referrer leaks
  Attack: URL contains sensitive data, sent to third parties
  Protection: Limits what referrer info gets sent
```

**Cookie Security Analysis**:

```python
for cookie in response.cookies:
    # Check security flags
    is_httponly = 'HttpOnly' in cookie  # Prevents JavaScript theft
    is_secure = 'Secure' in cookie      # HTTPS only
    is_samesite = 'SameSite' in cookie  # CSRF protection
    
    # Assess security
    if is_httponly and is_secure and is_samesite:
        security = "EXCELLENT"
    elif is_httponly and is_secure:
        security = "GOOD"
    else:
        security = "WEAK"
```

**Security Grade Calculation**:

```python
# Count how many of 5 critical headers present
critical_headers = [
    'strict-transport-security',  # HSTS
    'content-security-policy',     # CSP
    'x-frame-options',             # Clickjacking
    'x-content-type-options',      # MIME sniffing
    'referrer-policy'              # Referrer
]

headers_present = sum(1 for h in critical_headers if h in response_headers)

# Grade assignment
grades = {
    5: 'A+',  # Perfect
    4: 'A',   # Very good
    3: 'B',   # Good
    2: 'C',   # Fair
    1: 'D',   # Poor
    0: 'F'    # Failing
}
```

**Output Structure**:

```json
{
  "status": "ok",
  "http_status": 200,
  "final_url": "https://www.example.com/",
  "redirect_chain": [
    "http://example.com → 301",
    "http://www.example.com → 301",
    "https://www.example.com → 200"
  ],
  "security_audit": {
    "grade": "A",
    "headers_present": 5,
    "headers_missing": 0,
    "score": 95
  },
  "security_headers": {
    "present": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
      "x-frame-options": "SAMEORIGIN",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin"
    },
    "missing": []
  },
  "cookies": [
    {
      "name": "session_id",
      "value": "abc123...",
      "domain": "example.com",
      "path": "/",
      "expires": "2026-08-06T14:30:00Z",
      "httponly": true,     // ✓ JavaScript can't steal it
      "secure": true,       // ✓ HTTPS only
      "samesite": "Strict"  // ✓ CSRF protected
    },
    {
      "name": "_ga",  // Google Analytics
      "httponly": false,   // ✗ JavaScript can read it
      "secure": true,
      "samesite": "Lax"
    }
  ]
}
```

**Real-World Example - Comparison**:

```
GitHub.com:
  Grade: A+ (All headers present)
  HSTS: ✓ Present
  CSP: ✓ Present (strict)
  X-Frame-Options: ✓ DENY
  Cookie Security: ✓ Excellent

Random Site:
  Grade: F (No headers)
  HSTS: ✗ Missing
  CSP: ✗ Missing
  X-Frame-Options: ✗ Missing
  Cookie Security: ✗ Weak (no flags)
```

**What Missing Headers Mean for Users**:

```
No HSTS:
  Risk: Attacker downgrades connection, intercepts data

No CSP:
  Risk: XSS vulnerability can inject malicious scripts

No X-Frame-Options:
  Risk: Clickjacking - embedded in fake iframe

No X-Content-Type-Options:
  Risk: Uploaded file might execute as wrong type

Weak Cookies:
  Risk: JavaScript malware steals session cookies
```

---

### 6. Web Technology Detection (`web_tech.py`)

**Purpose**: Identifies programming languages, frameworks, libraries, servers, and CDNs.

**Files**: `backend/modules/web_tech.py`

**Libraries Used**:
- Regex pattern matching (built-in Python)
- No external dependencies

**Scan Modes**:
- Standard: ✓ Yes (8 seconds)
- Deep: ✓ Yes (8 seconds)
- Single Module: ✓ Yes (5 seconds)

**Detection Methods** (in order of confidence):

```
Method 1: HTTP Headers (Very Reliable)
  Example: "Server: nginx/1.24.0"
  → Identifies: nginx, version 1.24.0

Method 2: X-Powered-By Header (Reliable)
  Example: "X-Powered-By: Express"
  → Identifies: Express.js web framework

Method 3: Meta Tags in HTML (Reliable)
  Example: <meta name="generator" content="WordPress 6.2.1">
  → Identifies: WordPress CMS, version 6.2.1

Method 4: Cookie Names (Good Indicator)
  Example: "__rails_cookie=..."
  → Identifies: Ruby on Rails

Method 5: URL Patterns (Less Reliable)
  Example: /wp-admin/, /wp-content/
  → Identifies: WordPress (many sites mimic this)

Method 6: Response Body Analysis (Low Confidence)
  Example: <!-- Angular Application -->
  → Identifies: Angular (but could be outdated comment)
```

**Common Signatures**:

```python
SIGNATURES = {
    'Apache': {
        'headers': ['Server: Apache'],
        'meta': []
    },
    'Nginx': {
        'headers': ['Server: nginx'],
        'meta': []
    },
    'WordPress': {
        'urls': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
        'meta': ['generator.*wordpress'],
        'headers': []
    },
    'React': {
        'urls': [],
        'meta': [],
        'html': ['id="root"', 'id="__next"', 'id="app"']
    },
    'Cloudflare': {
        'headers': ['CF-RAY:', 'CF-Cache-Status:'],
        'cookies': ['__cfruid']
    },
    'jQuery': {
        'html': ['jquery.min.js', 'jquery-'],
        'script': ['jQuery', '$']
    }
}
```

**Output Structure**:

```json
{
  "status": "ok",
  "technologies": {
    "web_servers": [
      {
        "name": "Nginx",
        "version": "1.24.0",
        "confidence": 0.99,
        "detected_via": "Server header"
      }
    ],
    "programming_languages": [
      {
        "name": "JavaScript",
        "confidence": 0.95,
        "detected_via": "Script tags, file extensions"
      },
      {
        "name": "Python",
        "confidence": 0.80,
        "detected_via": "X-Powered-By header"
      }
    ],
    "frameworks": [
      {
        "name": "React",
        "version": "18.0.0",
        "confidence": 0.90,
        "detected_via": "Meta tag, root div id"
      },
      {
        "name": "Express.js",
        "confidence": 0.85,
        "detected_via": "X-Powered-By header"
      }
    ],
    "cms": [
      {
        "name": "WordPress",
        "version": "6.2.1",
        "confidence": 0.95,
        "detected_via": "Generator meta tag, /wp-admin/"
      }
    ],
    "cdn": [
      {
        "name": "Cloudflare",
        "confidence": 0.99,
        "detected_via": "CF-RAY header"
      }
    ],
    "analytics": [
      {
        "name": "Google Analytics",
        "version": "4",
        "confidence": 0.98,
        "detected_via": "GA4 script tag"
      }
    ]
  }
}
```

**Real-World Examples**:

```
Facebook.com:
  Server: Custom (Facebook's own)
  Languages: JavaScript, PHP
  Frameworks: React
  CDN: Facebook's own

WordPress.com Blog:
  Server: Nginx
  CMS: WordPress 6.2.1
  CDN: Cloudflare
  Analytics: Google Analytics

GitHub.com:
  Server: GitHub's custom
  Languages: JavaScript, Ruby
  Frameworks: Rails, React
  CDN: Cloudflare
```

**Security Value**:

1. **Outdated Technology** → Known vulnerabilities possible
2. **Specific Version** → Can search for CVEs for that version
3. **Unusual Stack** → Might indicate custom security
4. **Multiple CDNs** → Unusual, might be load balanced
5. **No framework detected** → Static site or well-hidden stack

---

### 7. Port Scanner (`port_scanner.py`)

**Purpose**: Discovers open ports and running services via TCP connection attempts.

**Files**: `backend/modules/port_scanner.py`

**Libraries Used**:
- `asyncio` - Async socket operations
- `socket` - TCP connections

**Scan Modes**:
- Standard: ✓ Yes (100 ports, 60 seconds)
- Deep: ✓ Yes (1000 ports, 180 seconds)
- Single Module: ✓ Yes (100 ports, 60 seconds)

**Concurrency**: 300 simultaneous connections

**How Port Scanning Works**:

```python
async def scan_port(ip, port):
    """
    Attempts to connect to a port.
    Success = port open
    Refused = port closed
    Timeout = port filtered (firewall)
    """
    try:
        # Try to connect with 3-second timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=3.0
        )
        
        # Connection succeeded = port is OPEN
        # Try to read service banner
        try:
            banner = await reader.read(1024)
            return {'port': port, 'state': 'open', 'banner': banner}
        except:
            return {'port': port, 'state': 'open', 'banner': 'No banner'}
            
    except asyncio.TimeoutError:
        # No response = FILTERED (firewall blocking)
        return {'port': port, 'state': 'filtered'}
        
    except ConnectionRefusedError:
        # Connection refused = CLOSED (host up, port closed)
        return {'port': port, 'state': 'closed'}
```

**Port States Explained**:

| State | Meaning | What It Means |
|---|---|---|
| **Open** | TCP handshake successful | Service is listening and responding |
| **Closed** | Connection refused | Host is up, but no service on this port |
| **Filtered** | No response (timeout) | Firewall is probably blocking (stealth) |
| **Unfiltered** | No response | Can't determine state |

**Common Ports Tested** (Top 100):

```
Web Services:
  80 - HTTP (web)
  443 - HTTPS (secure web)
  8080 - HTTP alternate
  8443 - HTTPS alternate

Databases:
  3306 - MySQL
  5432 - PostgreSQL
  27017 - MongoDB
  6379 - Redis

Remote Access:
  22 - SSH
  3389 - RDP (Windows)
  5900 - VNC

Mail:
  25 - SMTP (send email)
  110 - POP3 (receive email)
  143 - IMAP (receive email)
  587 - SMTP (secure)

Other:
  21 - FTP
  23 - Telnet
  53 - DNS
```

**Banner Grabbing** (Reading Service Identifiers):

```
Port 22 Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
  → Can identify SSH version and OS

Port 80 Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"
  → Can identify web server

Port 3306 Banner: "5.7.33-0ubuntu0.18.04.1-log..."
  → Can identify MySQL version
```

**Output Structure**:

```json
{
  "status": "ok",
  "scan_type": "standard",  // or "deep"
  "ports_tested": 100,      // or 1000 for deep
  "results": {
    "open": [
      {
        "port": 22,
        "service": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.9p1",
        "state": "open"
      },
      {
        "port": 80,
        "service": "HTTP",
        "banner": "HTTP/1.1 200 OK",
        "state": "open"
      },
      {
        "port": 443,
        "service": "HTTPS",
        "banner": "TLS 1.3",
        "state": "open"
      }
    ],
    "closed": 76,           // Host replied, port closed
    "filtered": 21          // Firewall blocking (no response)
  },
  "summary": {
    "open_count": 3,
    "closed_count": 76,
    "filtered_count": 21,
    "firewall_detected": true
  }
}
```

**Real-World Example - Typical Web Server**:

```
Open Ports:
  22/TCP - SSH (remote access for admin)
  80/TCP - HTTP (web traffic)
  443/TCP - HTTPS (secure web)

Closed:
  23/TCP - Telnet (intentionally closed, dangerous)
  3306/TCP - MySQL (not exposed, good practice)

Filtered:
  3389/TCP - RDP (blocked by firewall)
  25/TCP - SMTP (blocked by firewall)
```

**Security Insights**:

1. **Too many open ports** → Unnecessary services running (reduce attack surface)
2. **SSH on port 22** → Standard, might get brute-force attempts (use keys, not passwords)
3. **Port 3306 (MySQL) open** → Database exposed to internet (very bad)
4. **Custom ports** → Service hiding on non-standard port (obscurity, not security)
5. **Filtered ports** → Firewall working correctly

---

### 8. Subdomain Discovery (`subdomain_finder.py`)

**Purpose**: Discovers subdomains using passive OSINT and DNS brute-forcing.

**Files**: `backend/modules/subdomain_finder.py`

**Libraries Used**:
- `aiohttp` - Async HTTP queries to OSINT APIs
- `dnspython` - DNS lookups
- `asyncio` - Concurrent operations
- `subprocess` - theHarvester tool

**Scan Modes**:
- Standard: ✓ Yes (3500+ words, 180 seconds)
- Deep: ✓ Yes (3500+ words, 180 seconds)
- Single Module: ✓ Yes (2000 words, 90 seconds - OPTIMIZED)

**Concurrency**: 300 simultaneous DNS queries

**Discovery Sources** (4 Methods):

```
Method 1: Certificate Transparency (crt.sh)
  • Public log of all SSL certificates issued
  • When cert issued, domain name logged publicly
  • Query: SELECT * FROM certs WHERE domain LIKE '%.example.com'
  • Finds: ALL documented subdomains with SSL certs
  • Accuracy: 100% (if cert was issued)
  
Method 2: HackerTarget OSINT
  • Database of scanned subdomains
  • From web crawls and DNS data
  • Query: GET /api/hostsearch?q=example.com
  • Finds: Previously documented subdomains
  • Accuracy: Good for common subdomains
  
Method 3: Shodan Reverse IP
  • Shodan indexes all internet devices
  • Reverse IP lookup: what domains point to IP?
  • Query: GET /internetdb/{ip}
  • Finds: All domains on same server
  • Accuracy: Good if multiple domains on one IP
  
Method 4: DNS Brute-Force
  • Try common prefixes: www, api, mail, dev, staging...
  • For each prefix, do DNS lookup
  • Finds: Hidden/undocumented subdomains
  • Accuracy: Only finds if DNS resolves
```

**Brute-Force Wordlist Strategy**:

```python
# For Standard/Deep scans: Use FULL wordlist
COMMON_SUBDOMAINS = [
    # Base: ~126 words
    "www", "mail", "ftp", "smtp", "pop", "imap", "api", "admin",
    # Numbered variations (1-50)
    "api1", "api2", ... "api50",
    "web1", "web2", ... "web50",
    "dev1", "dev2", ... "dev50",
    # Microservice combinations
    "user-service", "auth-api", "payment-api",
    # Many more...
]
# Total: 3500+ words

# For Single Module checks: Use QUICK wordlist (optimized)
COMMON_SUBDOMAINS_QUICK = [
    # Base: ~126 words (same as above)
    "www", "mail", "ftp", "smtp", "pop", "imap", "api", "admin",
    # Numbered variations (1-30 only, not 1-50)
    "api1", "api2", ... "api30",  # REDUCED from 50
    "web1", "web2", ... "web30",
    # Fewer microservice combos
    "user-service", "auth-api",
]
# Total: ~2000 words (FASTER but still thorough)
```

**DNS Lookup Process**:

```python
async def check_subdomain(prefix, domain):
    """
    Try to resolve subdomain.domain
    """
    subdomain = f"{prefix}.{domain}"
    
    try:
        # Async DNS lookup with 2-second timeout
        ips = await dns_resolve(subdomain, timeout=2.0)
        
        if ips:  # DNS resolved successfully
            return {
                'subdomain': subdomain,
                'ips': ips,
                'resolved': True,
                'source': 'bruteforce'
            }
    except:
        pass  # No DNS record, not a valid subdomain
```

**Output Structure**:

```json
{
  "status": "ok",
  "total_discovered": 42,
  "discovery_sources": {
    "certificate_transparency": {
      "count": 15,
      "subdomains": ["www", "api", "mail", ...]
    },
    "hackertarget": {
      "count": 8,
      "subdomains": ["staging", "dev", ...]
    },
    "shodan_reverse": {
      "count": 5,
      "subdomains": ["cdn", "api-alt", ...]
    },
    "dns_bruteforce": {
      "count": 14,
      "subdomains": ["test", "admin", ...]
    }
  },
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "ips": ["93.184.216.34"],
      "sources": ["crt.sh", "hackertarget"],
      "resolved": true
    },
    {
      "subdomain": "api.example.com",
      "ips": ["93.184.216.35", "93.184.216.36"],
      "sources": ["bruteforce", "crt.sh"],
      "resolved": true
    },
    {
      "subdomain": "staging.example.com",
      "ips": ["192.168.1.100"],
      "sources": ["bruteforce"],
      "resolved": true,
      "private_ip": true  // ⚠️ Warning - private IP
    }
  ],
  "statistics": {
    "unique_subdomains": 42,
    "resolved_count": 40,
    "unresolved_count": 2,
    "scan_time": 145.2
  }
}
```

**Real-World Example - Google.com**:

```
From crt.sh:
  • accounts.google.com
  • mail.google.com
  • drive.google.com
  • docs.google.com
  (Many more from issued certificates)

From Shodan:
  • *.google.com (wildcard)
  • backup.google.com

From Brute-Force:
  • (None found - Google uses hidden/internal subdomains)

Result: ~50+ subdomains discovered
```

**Security Value**:

1. **Staging/Dev subdomains** → Often less secure, might be exploitable
2. **Admin subdomains** → High-value targets
3. **API subdomains** → May have different auth/security
4. **Mail/SMTP subdomains** → Email security risks
5. **Private IP subdomains** → VPN/internal infrastructure exposed

---

### 9. Directory Enumeration (`directory_enum.py`)

**Purpose**: Discovers accessible web paths and sensitive files.

**Files**: `backend/modules/directory_enum.py`

**Libraries Used**:
- `aiohttp` - Async HTTP requests

**Scan Modes**:
- Standard: ✗ No (requires Deep mode)
- Deep: ✓ Yes (200 paths, 180 seconds)
- Single Module: ✓ Yes (200 paths, 120 seconds)

**Concurrency**: 200 simultaneous HTTP requests

**Paths Tested** (~200 common paths):

```
Configuration Files:
  /.env, /.env.local, /.env.example
  /config.php, /config.json, /config.xml
  /web.config, /appsettings.json

Sensitive Directories:
  /admin, /administrator, /wp-admin
  /backup, /backups, /bak
  /private, /confidential, /secret

Git Repositories:
  /.git, /.gitignore, /git.zip
  /.hg (Mercurial), /.svn (Subversion)

Database Files:
  /database.sql, /db.sql, /dump.sql
  /mysql.sql, /backup.sql
  /database.yml, /database.json

Build/Source:
  /node_modules, /package.json
  /pom.xml (Java), /requirements.txt (Python)
  /Gemfile (Ruby), /composer.json (PHP)

Cache/Temp:
  /cache, /temp, /tmp, /logs
  /.cache, /.tmp

And many more...
```

**Wildcard Detection** (Critical for Accuracy):

```python
# Step 1: Test a random nonexistent path
test_path = f'/random_{uuid.uuid4()}_xyz12345'
resp = await session.get(f'https://{domain}{test_path}')

if resp.status == 200:  # Server returns 200 for ANYTHING
    # This is a wildcard! Save the pattern
    wildcard_response = {
        'status': resp.status,
        'content_length': len(resp.text),
        'redirect_url': resp.url
    }
    
# Step 2: During path fuzzing, filter out matches
for path in PATHS:
    resp = await session.get(f'https://{domain}{path}')
    
    # Compare with wildcard pattern
    if is_similar_to_wildcard(resp, wildcard_response):
        continue  # Skip false positive
    
    if resp.status != 404:
        results.append(path)  # Real finding!
```

**Why Wildcard Detection Matters**:

```
Website 1 (No Wildcard):
  /admin → 403 Forbidden ✓ Real finding
  /random_xyz → 404 Not Found ✓ Correct response
  
Website 2 (With Wildcard):
  /admin → 200 OK (returns home page)
  /random_xyz → 200 OK (also returns home page)
  WITHOUT wildcard detection: Think /admin exists ✗ FALSE POSITIVE
  WITH detection: Filter it out ✓ CORRECT
```

**Status Code Interpretation**:

| Status | Meaning | Action |
|---|---|---|
| **200 OK** | File/directory exists | ✓ Found! |
| **301/302** | Redirect | ✓ Found (but redirects) |
| **403 Forbidden** | Exists but no permission | ✓ Found (but protected) |
| **404 Not Found** | Doesn't exist | ✗ Keep looking |
| **500 Server Error** | Server error | ? Might exist |

**Output Structure**:

```json
{
  "status": "ok",
  "wildcard_detected": false,
  "directories_found": 8,
  "results": [
    {
      "path": "/.env",
      "status": 200,
      "content_length": 245,
      "location": "/.env (no redirect)",
      "found_method": "HTTP GET",
      "risk": "HIGH"  // Config file with secrets
    },
    {
      "path": "/.git",
      "status": 301,
      "location": "/.git/",
      "content_length": 0,
      "risk": "HIGH"  // Git repo exposed
    },
    {
      "path": "/admin",
      "status": 403,
      "content_length": 162,
      "location": "/admin (no redirect)",
      "risk": "MEDIUM"  // Admin panel but protected
    },
    {
      "path": "/backup.sql",
      "status": 200,
      "content_length": 15000,
      "location": "/backup.sql",
      "risk": "CRITICAL"  // Database backup exposed
    },
    {
      "path": "/node_modules/express/package.json",
      "status": 200,
      "content_length": 8234,
      "risk": "LOW"  // Framework files (expected)
    }
  ],
  "statistics": {
    "total_tested": 200,
    "found_count": 8,
    "success_rate": 4
  }
}
```

**Real-World Findings**:

```
Found: /.env
  Risk: CRITICAL
  Why: Environment config file with database passwords, API keys

Found: /backup.sql (5MB)
  Risk: CRITICAL
  Why: Entire database dump publicly accessible

Found: /.git/config
  Risk: HIGH
  Why: Git repository exposed, can download entire source code

Found: /admin
  Risk: MEDIUM
  Why: Admin panel accessible (but might need login)

Found: /node_modules/
  Risk: LOW
  Why: Dependencies folder (expected, not sensitive)
```

**Security Insights**:

1. **/.env exists** → Secrets exposed (database creds, API keys)
2. **/.git exists** → Source code might be downloadable
3. **/backup files** → Old/sensitive data exposed
4. **/config files** → System configuration exposed
5. **/admin exists** → Admin panel location known

---

### 10. Cloud Provider Detection (`cloud_provider.py`)

**Purpose**: Identifies hosting platform (AWS, Google Cloud, Azure, etc.).

**Files**: `backend/modules/cloud_provider.py`

**Libraries Used**:
- `ipaddress` (Python built-in) - IP range matching

**Scan Modes**:
- Standard: ✓ Yes (5 seconds)
- Deep: ✓ Yes (5 seconds)
- Single Module: ✓ Yes (3 seconds)

**How It Works**:

```python
# Each cloud provider owns specific IP ranges
# Example: AWS owns 3.0.0.0/8 (52 million IPs)

target_ip = ipaddress.ip_address('52.1.2.3')  # AWS IP

for provider, cidrs in cloud_ranges.items():
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr)
        if target_ip in network:
            return f"Found in {provider}: {cidr}"
```

**Cloud Providers Detected**:

| Provider | Examples of IPs | Use Cases |
|---|---|---|
| **AWS** | 3.0.0.0/8, 13.0.0.0/8 | Web hosting, databases, compute |
| **Google Cloud** | 35.184.0.0/13, 35.192.0.0/11 | App engine, compute engine |
| **Microsoft Azure** | 13.64.0.0/11, 40.64.0.0/10 | VMs, app services |
| **Cloudflare** | 104.16.0.0/12, 104.17.0.0/12 | CDN, DDoS protection |
| **DigitalOcean** | 45.32.0.0/14 | VPS hosting |
| **Oracle Cloud** | 129.213.0.0/16, ... | Enterprise cloud |
| **Linode** | 45.33.0.0/16, ... | VPS hosting |
| **Vultr** | 45.32.0.0/14 | VPS hosting |

**IP Range Example** (AWS):

```
3.0.0.0 - 3.255.255.255     (All of 3.0.0.0/8 = 16 million IPs)
13.0.0.0 - 13.255.255.255   (All of 13.0.0.0/8 = 16 million IPs)
15.0.0.0 - 15.255.255.255   (All of 15.0.0.0/8 = 16 million IPs)
... and dozens more
```

**Output Structure**:

```json
{
  "status": "ok",
  "ip": "52.1.2.3",
  "provider": "AWS",
  "network": "52.0.0.0/11",
  "region": "us-east-1",  // If identifiable
  "confidence": 0.99,
  "region_details": {
    "country": "United States",
    "city": "N/A (AWS distributed)",
    "service": "EC2 (Elastic Compute Cloud)"
  }
}
```

**Real-World Examples**:

```
IP: 54.234.56.78
Provider: AWS
Region: us-east-1
Service: Likely web server

IP: 35.201.123.45
Provider: Google Cloud
Region: us-central1
Service: Likely App Engine or Compute Engine

IP: 104.16.123.45
Provider: Cloudflare
Service: CDN / DDoS protection
Note: NOT actual server, this is Cloudflare's IP (proxied)
```

**Security Insights**:

1. **Cloudflare detected** → Site uses CDN (faster, DDoS protected)
2. **AWS detected** → Commercial hosting (likely legitimate)
3. **Unknown provider** → Might be self-hosted or smaller provider
4. **Multiple cloud IPs** → Likely load balanced across clouds

---

### 11. WAF Detection (`waf_detect.py`)

**Purpose**: Identifies Web Application Firewall products protecting the site.

**Files**: `backend/modules/waf_detect.py`

**Libraries Used**:
- `aiohttp` - HTTP requests

**Scan Modes**:
- Standard: ✓ Yes (15 seconds)
- Deep: ✓ Yes (15 seconds)
- Single Module: ✓ Yes (10 seconds)

**Detection Method**:

```python
# Step 1: Send baseline request
baseline_resp = await session.get(f'https://{domain}/')
baseline_status = baseline_resp.status

# Step 2: Send attack payloads
attack_payloads = [
    "' OR '1'='1",                    # SQL injection
    "<script>alert(1)</script>",      # XSS
    "../../../etc/passwd",            # Path traversal
    "1' UNION SELECT NULL--",         # SQL union
    "<iframe src=evil.com></iframe>", # Iframe injection
]

# Step 3: Compare responses
for payload in attack_payloads:
    attack_resp = await session.get(f'https://{domain}/?input={payload}')
    
    # Check if response changed
    if attack_resp.status != baseline_status:
        # WAF likely blocked it!
        blocked_payloads.append(payload)
        waf_signatures = match_signatures(attack_resp)

# Step 4: Match against known WAF signatures
```

**WAF Signature Detection**:

```python
WAF_SIGNATURES = {
    'Cloudflare': {
        'status_codes': [403],
        'response_body': [
            '1020: Access Denied',
            'cf_clearance'
        ],
        'headers': ['CF-RAY'],
        'confidence': 0.99
    },
    'AWS WAF': {
        'status_codes': [403],
        'response_body': ['AccessDenied'],
        'headers': ['x-amzn-ErrorType'],
        'confidence': 0.95
    },
    'Akamai': {
        'status_codes': [403],
        'response_body': ['Akamai', 'denied by AK'],
        'headers': [],
        'confidence': 0.90
    },
    'Imperva': {
        'status_codes': [403, 404],
        'response_body': ['Unauthorized', 'support.imperva.com'],
        'headers': ['X-Imperva'],
        'confidence': 0.90
    },
    # ... 20+ more WAFs
}
```

**Output Structure**:

```json
{
  "status": "ok",
  "waf_detected": true,
  "waf_product": "Cloudflare",
  "confidence": 0.99,
  "evidence": {
    "blocked_payloads": 5,
    "matching_signatures": [
      "CF-RAY header present",
      "403 Forbidden on SQLi payload",
      "Response body contains '1020: Access Denied'"
    ],
    "waf_response_type": "Custom error page"
  },
  "waf_capabilities": {
    "blocks_sql_injection": true,
    "blocks_xss": true,
    "blocks_path_traversal": true,
    "rate_limiting": true,
    "ddos_protection": true,
    "bot_protection": true
  },
  "implications": {
    "attack_difficulty": "HIGH",
    "bypass_difficulty": "VERY HIGH",
    "recommendation": "This site is well-protected. Attacks unlikely to succeed."
  }
}
```

**Common WAFs Detected**:

| WAF | Detection Method | Confidence |
|---|---|---|
| **Cloudflare** | CF-RAY header, error page | 99% |
| **AWS WAF** | AWS error page, headers | 95% |
| **Akamai** | Response body signatures | 90% |
| **Imperva** | Support email in error | 90% |
| **Citrix NetScaler** | Header fingerprints | 85% |
| **ModSecurity** | Error page patterns | 80% |

**Real-World Example - GitHub.com**:

```
Detected: Cloudflare
Confidence: 99%
Evidence: CF-RAY header, custom Cloudflare error pages
Attack Test Result: SQL injection blocked (403)
Conclusion: Well-protected, attacks unlikely to succeed
```

**Security Insights**:

1. **WAF detected** → Site is protected (good security)
2. **No WAF** → Attacks might succeed (lower security)
3. **Specific WAF known** → Can look up known bypasses
4. **DDoS protection** → Can withstand volume attacks
5. **Bot protection** → Automated scanning will be blocked

---

### 12. CMS Fingerprinting (`cms_fingerprint.py`)

**Purpose**: Identifies Content Management Systems (WordPress, Shopify, etc.).

**Files**: `backend/modules/cms_fingerprint.py`

**Libraries Used**:
- `aiohttp` - HTTP requests
- Regex pattern matching

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (8 seconds)

**Detection Methods** (in order of reliability):

```
Method 1: Meta Tag (Very Reliable)
  <meta name="generator" content="WordPress 6.2.1" />
  → Found in HTML, directly tells you CMS

Method 2: WordPress-Specific URLs
  /.wp-includes/        → WordPress
  /wp-content/          → WordPress
  /wp-admin/            → WordPress
  /wp-json/             → WordPress REST API

Method 3: Joomla Signatures
  /components/          → Joomla
  /libraries/           → Joomla
  /images/              → Joomla (usually)

Method 4: Drupal Signatures
  /sites/default/       → Drupal
  /modules/             → Drupal
  /themes/              → Drupal

Method 5: Shopify
  /cdn/shop/            → Shopify
  Shopify-specific headers

Method 6: Source Code Analysis
  Comment patterns
  CSS/JS file locations
  Error message formats
```

**WordPress Detection Logic**:

```python
# Method 1: Direct meta tag
if 'generator.*wordpress' in html_content:
    return {
        'cms': 'WordPress',
        'version': extract_version(match),
        'confidence': 0.99
    }

# Method 2: WordPress URLs
wordpress_paths = [
    '/wp-admin/',
    '/wp-includes/',
    '/wp-content/',
    '/wp-json/'
]

for path in wordpress_paths:
    if path_accessible(f'https://{domain}{path}'):
        return {
            'cms': 'WordPress',
            'version': 'Unknown',
            'confidence': 0.95,
            'evidence': [path]
        }
```

**Output Structure**:

```json
{
  "status": "ok",
  "cms_detected": true,
  "cms": {
    "name": "WordPress",
    "version": "6.2.1",
    "confidence": 0.99,
    "detected_via": "Meta generator tag"
  },
  "evidence": {
    "meta_tags": [
      "generator: WordPress 6.2.1"
    ],
    "accessible_paths": [
      "/wp-admin/",
      "/wp-content/",
      "/wp-includes/"
    ],
    "fingerprints": [
      "WordPress REST API endpoint at /wp-json/"
    ]
  },
  "cms_version_info": {
    "current_version": "6.5.0",
    "installed_version": "6.2.1",
    "is_outdated": true,
    "available_updates": [
      {
        "version": "6.3.0",
        "release_date": "2023-08-09",
        "security": false
      },
      {
        "version": "6.4.0",
        "release_date": "2023-11-07",
        "security": false
      },
      {
        "version": "6.5.0",
        "release_date": "2024-04-02",
        "security": true
      }
    ]
  },
  "security_assessment": {
    "version_status": "OUTDATED",
    "vulnerability_risk": "HIGH",
    "known_cves": [
      "CVE-2023-39999 - XSS vulnerability",
      "CVE-2023-40028 - Authentication bypass"
    ]
  }
}
```

**CMSs Detected**:

| CMS | Detection Method | Confidence |
|---|---|---|
| **WordPress** | Meta tag, /wp-admin/ | 99% |
| **Shopify** | Store URLs, Shopify headers | 98% |
| **Joomla** | Meta tag, /administrator/ | 95% |
| **Drupal** | Meta tag, /sites/default/ | 90% |
| **Magento** | Specific URLs, headers | 90% |
| **Wix** | JavaScript signatures | 85% |
| **Squarespace** | Domain patterns, headers | 80% |

**Real-World Examples**:

```
WordPress.com Blog:
  CMS: WordPress 6.2.1
  Confidence: 99%
  Evidence: Meta tag, /wp-admin/ accessible, /wp-json/ present

E-commerce Store:
  CMS: Shopify
  Confidence: 98%
  Evidence: Shopify headers, .shopifycdn.com resources

Corporate Site:
  CMS: Joomla 4.0
  Confidence: 95%
  Evidence: Meta tag, /components/ accessible
```

**Security Implications**:

1. **Known CMS** → Known vulnerabilities exist for that version
2. **Outdated version** → More vulnerabilities available
3. **Specific version known** → Can search for CVEs
4. **WordPress detected** → 40% of internet uses it (common target)

---

---

### 13. CORS & Open Redirect Testing (`cors_check.py`)

**Purpose**: Tests for CORS misconfigurations and open redirect vulnerabilities.

**Files**: `backend/modules/cors_check.py`

**Libraries Used**:
- `aiohttp` - HTTP requests with custom headers

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (8 seconds)

**CORS Testing Logic**:

```python
# Step 1: Send request WITH Origin header
headers = {'Origin': 'https://evil.com'}
resp = await session.get(f'https://{domain}/', headers=headers)

# Step 2: Check CORS response headers
cors_origin = resp.headers.get('Access-Control-Allow-Origin')
cors_credentials = resp.headers.get('Access-Control-Allow-Credentials')
cors_methods = resp.headers.get('Access-Control-Allow-Methods')
cors_headers = resp.headers.get('Access-Control-Allow-Headers')

# Step 3: Analyze for misconfiguration
if cors_origin == '*':
    # VULNERABILITY: Allows ANY origin
    vulnerability = "Overly permissive CORS (allows any origin)"

elif cors_origin == 'https://evil.com':
    # VULNERABILITY: Reflected origin - blindly trusts Origin header
    vulnerability = "Reflected CORS (trusts Origin header)"

elif cors_origin and cors_credentials == 'true':
    # VULNERABILITY: Credentials leaked to any origin
    vulnerability = "CORS with credentials (can leak auth)"
```

**CORS Attack Scenarios**:

```
Scenario 1: Overly Permissive CORS (Access-Control-Allow-Origin: *)
  ┌─ Evil Site (evil.com)
  │  ├─ Loads JavaScript in browser
  │  └─ Calls API on example.com
  │     └─ Browser asks: Is this allowed?
  │        └─ example.com says: "Yes, anyone can call me (*)"
  │           └─ JavaScript gets access to API response
  │
  Risk: Attacker steals user data via API

Scenario 2: Reflected CORS (trusts Origin header)
  ┌─ example.com doesn't have CORS header
  ├─ Attacker controls Origin header
  │  └─ Sends: Origin: https://evil.com
  │  └─ Server responds: Access-Control-Allow-Origin: https://evil.com
  │
  Risk: Same as above - attacker can call API

Scenario 3: CORS + Credentials
  ┌─ Browser sends: Origin: https://evil.com
  ├─ Server responds:
  │  ├─ Access-Control-Allow-Origin: https://evil.com
  │  └─ Access-Control-Allow-Credentials: true
  │
  Risk: Attacker gets access to authenticated user data
```

**Open Redirect Testing**:

```python
# Parameters to test for redirects
redirect_params = [
    'url',        # ?url=https://evil.com
    'redirect',   # ?redirect=https://evil.com
    'next',       # ?next=https://evil.com
    'target',     # ?target=https://evil.com
    'returnurl',  # ?returnurl=https://evil.com
    'return_to',  # ?return_to=https://evil.com
]

for param in redirect_params:
    attack_url = f'https://{domain}/?{param}=https://evil.com'
    resp = await session.get(attack_url, allow_redirects=False)
    
    if resp.status in [301, 302, 303, 307, 308]:
        # Redirect found!
        location = resp.headers.get('Location')
        
        if 'evil.com' in location:
            # VULNERABILITY: Open redirect
            vulnerability = f"Open redirect via {param} parameter"
```

**Output Structure**:

```json
{
  "status": "ok",
  "cors_analysis": {
    "cors_enabled": true,
    "misconfiguration_detected": false,
    "allowed_origins": ["https://example.com", "https://api.example.com"],
    "allow_credentials": false,
    "allowed_methods": ["GET", "POST", "OPTIONS"],
    "allowed_headers": ["Content-Type", "Authorization"],
    "max_age": 86400
  },
  "open_redirects": {
    "vulnerabilities_found": 1,
    "redirects": [
      {
        "parameter": "url",
        "vulnerable": true,
        "redirect_target": "https://attacker.com",
        "status_code": 302
      }
    ]
  },
  "security_assessment": {
    "cors_risk": "LOW",
    "redirect_risk": "MEDIUM",
    "overall_risk": "MEDIUM"
  }
}
```

---

### 14. Email Harvesting (`email_gather.py`)

**Purpose**: Discovers email addresses associated with the domain.

**Files**: `backend/modules/email_gather.py`

**Libraries Used**:
- `subprocess` - Runs theHarvester CLI tool
- `aiohttp` - API queries

**Scan Modes**:
- Standard: ✓ Yes (60 seconds)
- Deep: ✓ Yes (130 seconds)
- Single Module: ✓ Yes (60 seconds)

**Email Discovery Sources**:

```
theHarvester searches multiple sources:

1. Google Search
   • Indexes public web pages
   • Finds emails in PDFs, documents
   • Finds emails in page text

2. LinkedIn
   • Company profiles
   • Employee profiles
   • Email patterns from profiles

3. Twitter
   • Tweets mentioning domain
   • User profiles

4. Shodan
   • Internet device index
   • Banner grabs (SMTP banners contain emails)

5. Hunter.io
   • Email database
   • Patterns for domain

6. Clearbit
   • Company data
   • Employee information
```

**Email Pattern Recognition**:

```python
# Common email patterns discovered
patterns = [
    'firstname.lastname@example.com',
    'first@example.com',
    'fname@example.com',
    'f.lastname@example.com',
    'admin@example.com',
    'info@example.com',
    'support@example.com',
    'contact@example.com'
]
```

**Output Structure**:

```json
{
  "status": "ok",
  "total_emails": 23,
  "emails": [
    {
      "email": "john.doe@example.com",
      "source": "google",
      "context": "Found in PDF document on site",
      "verified": true
    },
    {
      "email": "jane.smith@example.com",
      "source": "linkedin",
      "context": "Employee profile",
      "verified": true
    },
    {
      "email": "admin@example.com",
      "source": "shodan",
      "context": "SMTP banner grab",
      "verified": false
    }
  ],
  "sources_used": ["google", "linkedin", "twitter", "shodan"],
  "harvester_errors": []
}
```

**Real-World Example**:

```
Domain: github.com
Emails Found: 150+
  • contact@github.com
  • support@github.com
  • security@github.com
  • Many employee emails from LinkedIn
  • Commit author emails from public repos
```

**Security Value**:

1. **Contact emails** → Can be used for phishing
2. **Support emails** → Social engineering targets
3. **Security contact** → For responsible disclosure (good!)
4. **Admin emails** → Sensitive targets
5. **Employee emails** → For social engineering campaigns

---

### 15. Reputation Check (AbuseIPDB + VirusTotal) (`reputation.py`)

**Purpose**: Queries threat intelligence APIs for malware/phishing reports.

**Files**: `backend/modules/reputation.py`

**Libraries Used**:
- `aiohttp` - API HTTP queries
- Rate limiting (asyncio.sleep)

**Scan Modes**:
- Standard: ✓ Yes (20 seconds, if API keys provided)
- Deep: ✓ Yes (20 seconds, if API keys provided)
- Single Module: ✓ Yes (15 seconds, if API keys provided)

**API Integration Details**:

**AbuseIPDB**:
```python
# Rate: 1000 requests/day = ~0.1 seconds minimum
# But actual rate is generous, no blocking observed

async def check_abuseipdb(ip):
    resp = await aiohttp.get(
        'https://api.abuseipdb.com/api/v2/check',
        params={
            'ipAddress': ip,
            'maxAgeInDays': 90  # Last 90 days
        },
        headers={'Key': ABUSEIPDB_API_KEY}
    )
    data = resp.json()
    return {
        'abuseConfidenceScore': data['abuseConfidenceScore'],  # 0-100
        'usageType': data['usageType'],  # residential, business, datacenter
        'isp': data['isp'],
        'domain': data['domain'],
        'totalReports': data['totalReports'],
        'lastReportedAt': data['lastReportedAt']
    }
```

**VirusTotal**:
```python
# Rate: 4 requests per minute = 1 request per 16 seconds
# Must implement backoff to avoid throttling

VIRUSTOTAL_BACKOFF = 16.0
last_request_time = 0

async def check_virustotal(domain):
    global last_request_time
    
    # Rate limiting
    elapsed = time.time() - last_request_time
    if elapsed < VIRUSTOTAL_BACKOFF:
        await asyncio.sleep(VIRUSTOTAL_BACKOFF - elapsed)
    
    # Query API
    resp = await aiohttp.get(
        f'https://www.virustotal.com/api/v3/domains/{domain}',
        headers={'x-apikey': VIRUSTOTAL_API_KEY}
    )
    
    data = resp.json()['data']['attributes']
    return {
        'last_analysis_stats': data['last_analysis_stats'],  # malicious, suspicious count
        'last_analysis_date': data['last_analysis_date'],
        'categories': data['categories'],
        'reputation': calculate_reputation(data)
    }
    
    last_request_time = time.time()
```

**Output Structure**:

```json
{
  "status": "ok",
  "target": "example.com",
  "abuseipdb": {
    "status": "ok",
    "ip": "93.184.216.34",
    "abuseConfidenceScore": 5,
    "usageType": "Content Delivery Network",
    "isp": "Verizon Business",
    "domain": "verizon.net",
    "totalReports": 3,
    "lastReportedAt": "2024-07-15T10:30:00Z",
    "reports": [
      {
        "reportedAt": "2024-07-15T10:30:00Z",
        "category": "Malware",
        "comment": "C&C server detected"
      }
    ]
  },
  "virustotal": {
    "status": "ok",
    "domain": "example.com",
    "last_analysis_stats": {
      "malicious": 0,
      "suspicious": 0,
      "undetected": 67,
      "harmless": 33
    },
    "vendors_breakdown": {
      "Fortinet": "clean",
      "Kaspersky": "clean",
      "Microsoft": "clean",
      "Symantec": "suspicious",
      "McAfee": "clean"
    },
    "last_analysis_date": "2024-08-05T14:22:10Z",
    "reputation": -3,  // Negative = potentially malicious
    "categories": {
      "uncategorized": true,
      "phishing": false,
      "malware": false
    }
  },
  "overall_assessment": {
    "threat_level": "LOW",
    "confidence": 0.95,
    "recommendation": "Safe to visit"
  }
}
```

**Interpreting Results**:

```
AbuseIPDB Score: 0-100
  0-5:     Clean (maybe false reports)
  6-25:    Suspicious
  26-75:   Bad
  76-100:  Very bad (malicious)

VirusTotal Detection Rate:
  0 vendors:    Clean (trusted by all)
  1-2 vendors:  Likely false positive
  3-10 vendors: Probably malicious
  10+ vendors:  Definitely malicious
```

**Real-World Example**:

```
Domain: known-malware-site.com
AbuseIPDB Score: 85 (Very bad)
  • 127 total reports
  • Last reported: 2024-08-01
  • Categories: Malware, C&C

VirusTotal: 47 vendors flagged it
  • Kaspersky: Trojan
  • Fortinet: Malware
  • McAfee: Malware
  • Symantec: Malware
  Result: DEFINITELY MALICIOUS
```

---

### 16. Reverse DNS (`dns_recon.py - PTR records`)

**Purpose**: Performs reverse DNS lookup (IP → hostname).

**Files**: `backend/modules/dns_recon.py` (secondary function)

**Libraries Used**:
- `socket` - Python's reverse DNS function
- `subprocess` - Fallback to nslookup command

**Scan Modes**:
- Standard: ✓ Yes (10 seconds)
- Deep: ✓ Yes (10 seconds)
- Single Module: ✓ Yes (5 seconds)

**How Reverse DNS Works**:

```python
# Method 1: Python socket (most common)
try:
    hostname, aliaslist, ipaddrlist = socket.gethostbyaddr('93.184.216.34')
    return hostname
except:
    # Method 2: Query nameserver for PTR record
    # PTR record is in reverse format: 34.216.184.93.in-addr.arpa
    ptr_query = f"socket.gethostbyaddr('93.184.216.34')"
    # Returns hostname like "example.com"

    # Method 3: Fallback to nslookup command (Windows)
    result = subprocess.run(
        ['nslookup', '-type=PTR', '93.184.216.34'],
        capture_output=True
    )
    # Parse output for "name = example.com"
```

**Output Structure**:

```json
{
  "status": "ok",
  "ip": "93.184.216.34",
  "reverse_dns": {
    "hostname": "example.com",
    "method": "socket.gethostbyaddr",
    "verified": true
  }
}
```

**Real-World Examples**:

```
IP: 8.8.8.8 (Google)
Reverse DNS: dns.google (but often just shows IP if not set)

IP: 1.1.1.1 (Cloudflare)
Reverse DNS: one.one.one.one

IP: 93.184.216.34 (ICANN)
Reverse DNS: example.com
```

**Security Insights**:

1. **Hostname matches domain** → Likely legitimate
2. **Hostname is different** → IP registered to different organization
3. **No reverse DNS** → Might indicate spam/malicious (but not always)
4. **Reverse DNS doesn't match** → Possible spoofing or hijacking

---

## Summary of All 16 Modules

**Quick Reference Table**:

| # | Module | Timeout | Concurrency | Key Libraries | Security Value |
|---|---|---|---|---|---|
| 1 | DNS Records | 10s | N/A | dnspython | Finds infrastructure |
| 2 | WHOIS | 10s | N/A | python-whois | Domain ownership, expiry |
| 3 | SSL Check | 12s | N/A | ssl, socket | Certificate validity |
| 4 | GeoIP | 8s | 3 parallel APIs | aiohttp | Server location |
| 5 | HTTP Headers | 10s | N/A | aiohttp | Security configuration |
| 6 | Web Tech | 8s | N/A | regex | Technology stack |
| 7 | Port Scanner | 60-180s | 300 connections | asyncio | Service discovery |
| 8 | Subdomains | 90-180s | 300 DNS queries | aiohttp, dnspython | Surface enumeration |
| 9 | Directories | 120-180s | 200 requests | aiohttp | Hidden files/paths |
| 10 | Cloud Provider | 3-5s | N/A | ipaddress | Hosting identification |
| 11 | WAF Detection | 10-15s | N/A | aiohttp | Defense detection |
| 12 | CMS Fingerprint | 8-10s | N/A | aiohttp | Platform identification |
| 13 | CORS/Redirect | 8-10s | N/A | aiohttp | Misconfiguration detection |
| 14 | Email Harvest | 60-130s | N/A | subprocess | Contact discovery |
| 15 | Reputation | 15-20s | Rate-limited | aiohttp | Threat intelligence |
| 16 | Reverse DNS | 5-10s | N/A | socket | Hostname lookup |

---

## How Modules Work Together

**Module Dependency Chain**:

```
Start with target: example.com
  │
  ├─→ [1] DNS Records
  │      └─→ Gets resolved IP
  │
  ├─→ [2] WHOIS
  │      └─→ Gets registration info
  │
  ├─→ [3] SSL Certificate
  │      └─→ Uses resolved IP
  │
  ├─→ [4] GeoIP
  │      └─→ Uses resolved IP → Gets location
  │
  ├─→ [5] HTTP Headers
  │      └─→ Queries domain → Gets security headers
  │
  ├─→ [6] Web Tech
  │      └─→ Queries domain → Detects stack
  │
  ├─→ [7] Port Scanner
  │      └─→ Uses resolved IP → Scans ports
  │
  ├─→ [8] Subdomains
  │      └─→ Finds subdomains → Resolves IPs
  │
  ├─→ [9] Directory Enum
  │      └─→ Queries domain → Finds paths
  │
  ├─→ [10] Cloud Provider
  │      └─→ Uses resolved IP → Detects cloud
  │
  ├─→ [11] WAF Detection
  │      └─→ Queries domain → Tests attack payloads
  │
  ├─→ [12] CMS Fingerprint
  │      └─→ Queries domain → Detects CMS
  │
  ├─→ [13] CORS/Redirect
  │      └─→ Queries domain → Tests CORS + redirects
  │
  ├─→ [14] Email Harvest
  │      └─→ Searches databases → Finds emails
  │
  ├─→ [15] Reputation
  │      └─→ Queries APIs → Gets threat data
  │
  └─→ [16] Reverse DNS
         └─→ Uses resolved IP → Gets hostname
```

**Module Grouping by Type**:

```
PASSIVE RECONNAISSANCE (Doesn't trigger alerts):
  • DNS Records
  • WHOIS
  • GeoIP
  • Reputation (threat intel)
  • Email Harvest
  • Cloud Provider

SEMI-ACTIVE (Might trigger alerts):
  • SSL Certificate
  • HTTP Headers
  • Web Technology
  • CMS Fingerprint

ACTIVE SCANNING (Definitely triggers alerts):
  • Port Scanner
  • Directory Enumeration
  • WAF Detection (sends attack payloads)
  • CORS Testing (tests security)
```

---

**Documentation Version**: 2.0 Complete | **Module Details**: Fully Expanded | **Last Updated**: August 2026



---

### 2. WHOIS Lookup

**Location**: `backend/modules/whois_lookup.py`

**Libraries Used**:
- `python-whois` - WHOIS queries (port 43)
- `aiohttp` - RDAP fallback (HTTP)

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 10 seconds
- Deep: 10 seconds
- Single module check: 5 seconds

**What It Finds**:
- Registrar
- Registration date
- Expiration date (with days remaining)
- Registrant info
- Nameservers
- Domain status (valid/expired/expiring)

**Output Example**:
```json
{
  "status": "ok",
  "registrar": "VeriSign Global Registry Services",
  "registration_date": "1995-08-14",
  "expiration_date": "2025-08-13",
  "days_remaining": 378,
  "status": "valid",
  "nameservers": ["ns1.example.com", "ns2.example.com"]
}
```

---

### 3. SSL Certificate Check

**Location**: `backend/modules/ssl_check.py`

**Libraries Used**:
- `ssl` (Python built-in) - TLS handshakes
- `socket` (Python built-in) - Network connections

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 12 seconds
- Deep: 12 seconds
- Single module check: 8 seconds

**What It Checks**:
- Common Name (domain)
- Issuer (Certificate Authority)
- Issue and expiration dates
- Public key strength (bits)
- Subject Alternative Names (other domains)
- TLS versions supported (1.0, 1.1, 1.2, 1.3)
- Cipher suites

**Output Example**:
```json
{
  "status": "ok",
  "common_name": "example.com",
  "issuer": "DigiCert Inc",
  "valid_from": "2023-11-01T00:00:00Z",
  "valid_until": "2025-11-30T23:59:59Z",
  "days_remaining": 478,
  "public_key_bits": 2048,
  "supported_protocols": ["TLSv1.2", "TLSv1.3"],
  "san_list": ["example.com", "www.example.com"]
}
```

---

### 4. GeoIP Location

**Location**: `backend/modules/geo_ip.py`

**Libraries Used**:
- `aiohttp` - Queries 3 GeoIP APIs concurrently

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 8 seconds
- Deep: 8 seconds
- Single module check: 5 seconds

**APIs Queried** (all run in parallel):
1. `ip-api.com` - Primary source
2. `freeipapi.com` - Backup
3. `ipinfo.io` - Backup

**What It Finds**:
- Country, city, state
- Latitude, longitude
- ISP name
- ASN (Autonomous System Number)
- Timezone
- Connection type (residential, corporate, datacenter)

**Output Example**:
```json
{
  "status": "ok",
  "country": "United States",
  "city": "Los Angeles",
  "latitude": 34.0522,
  "longitude": -118.2437,
  "isp": "ICANN",
  "asn": "AS12345",
  "timezone": "America/Los_Angeles",
  "map_url": "https://www.google.com/maps?q=34.0522,-118.2437"
}
```

---

### 5. HTTP Headers Security

**Location**: `backend/modules/http_headers.py`

**Libraries Used**:
- `aiohttp` - HTTP requests

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 10 seconds
- Deep: 10 seconds
- Single module check: 8 seconds

**Security Headers Checked**:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Cookie Flags Checked**:
- `HttpOnly` (prevents JavaScript access)
- `Secure` (HTTPS only)
- `SameSite` (CSRF protection)

**Output Example**:
```json
{
  "status": "ok",
  "http_status": 200,
  "security_grade": "A",
  "redirect_chain": ["http://example.com", "https://example.com"],
  "security_headers_present": {
    "strict-transport-security": "max-age=31536000",
    "x-frame-options": "SAMEORIGIN"
  },
  "security_headers_missing": ["content-security-policy"],
  "cookies": [
    {
      "name": "_ga",
      "httponly": false,
      "secure": true,
      "samesite": "Lax"
    }
  ]
}
```

---

### 6. Web Technology Detection

**Location**: `backend/modules/web_tech.py`

**Libraries Used**:
- Regex pattern matching (built-in)

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 8 seconds
- Deep: 8 seconds
- Single module check: 5 seconds

**Detection Methods**:
- HTTP headers analysis (`Server`, `X-Powered-By`)
- Cookie names
- HTML meta tags (especially `generator`)
- URL patterns

**What It Detects**:
- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, Python, Node.js)
- Frameworks (React, Angular, Django)
- CDNs (Cloudflare, Akamai)
- CMS (WordPress, Drupal)
- Libraries (jQuery, Bootstrap)

**Output Example**:
```json
{
  "status": "ok",
  "web_servers": ["Nginx/1.24.0"],
  "frameworks": ["React"],
  "cdn": ["Cloudflare"],
  "programming_languages": ["JavaScript", "Node.js"],
  "detected_technologies": [
    {"name": "Nginx", "version": "1.24.0"},
    {"name": "React", "version": "18.0.0"}
  ]
}
```

---

### 7. Port Scanner

**Location**: `backend/modules/port_scanner.py`

**Libraries Used**:
- `asyncio` - Concurrent socket connections

**Scan Modes**:
- Standard: Top 100 ports only
- Deep: Top 1000 ports

**Timeouts**:
- Standard: 60 seconds
- Deep: 180 seconds (3 minutes)
- Single module check: 60 seconds

**Concurrency**: 300 simultaneous connections

**Ports Tested**:
- Standard: 22, 80, 443, 3306, 5432, 8080, 27017, 6379, etc. (100 total)
- Deep: Same as Standard plus additional 900 ports

**Port States**:
- `open`: Connection successful
- `closed`: Connection refused (port exists but closed)
- `filtered`: Timeout (firewall blocking)

**Output Example**:
```json
{
  "status": "ok",
  "open_ports": [
    {"port": 22, "state": "open", "banner": "SSH-2.0-OpenSSH_8.9p1"},
    {"port": 80, "state": "open", "banner": "HTTP/1.1 301 Moved"},
    {"port": 443, "state": "open", "banner": "TLS 1.3"}
  ],
  "closed_ports": 76,
  "filtered_ports": 21
}
```

---

### 8. Subdomain Finder

**Location**: `backend/modules/subdomain_finder.py`

**Libraries Used**:
- `aiohttp` - OSINT API queries
- `dnspython` - DNS lookups
- `asyncio` - Concurrent operations
- `subprocess` - theHarvester tool

**Scan Modes**:
- Standard: Yes (3500+ word brute-force list)
- Deep: Yes (3500+ word brute-force list)
- Single module: Yes (2000 word quick list)

**Timeouts**:
- Standard/Deep: 180 seconds (3 minutes)
- Single module: 90 seconds

**Discovery Sources**:
1. **crt.sh** - Certificate Transparency logs
2. **HackerTarget** - OSINT database
3. **Shodan reverse IP** - Reverse IP lookup
4. **DNS brute-force** - Tests common prefixes

**Wordlist Sizes**:
- `COMMON_SUBDOMAINS_BASE`: ~126 words (base list)
- `COMMON_SUBDOMAINS_QUICK`: ~2000 words (for single checks)
- `COMMON_SUBDOMAINS`: 3500+ words (for full scans)

**Concurrency**: 300 simultaneous DNS queries

**Output Example**:
```json
{
  "status": "ok",
  "total_discovered": 23,
  "subdomains": [
    {"subdomain": "www.example.com", "ips": ["93.184.216.34"], "source": "crt.sh"},
    {"subdomain": "api.example.com", "ips": ["93.184.216.35"], "source": "bruteforce"}
  ],
  "sources_used": ["crt.sh", "hackertarget", "shodan", "bruteforce"]
}
```

---

### 9. Directory Enumeration

**Location**: `backend/modules/directory_enum.py`

**Libraries Used**:
- `aiohttp` - HTTP requests

**Scan Modes**:
- Standard: No
- Deep: Yes

**Timeouts**:
- Deep: 180 seconds (3 minutes)
- Single module: 120 seconds

**Paths Tested**: ~200 common paths

**Concurrency**: 200 simultaneous HTTP requests

**Wildcard Detection**: Tests fake paths first to filter false positives

**Common Paths Tested**:
- `/.env` (environment config)
- `/.git` (Git repository)
- `/admin` (admin panel)
- `/backup.sql` (database backup)
- `/config.php` (configuration)

**Output Example**:
```json
{
  "status": "ok",
  "directories_found": 5,
  "directories": [
    {"path": "/.git", "status": 301},
    {"path": "/admin", "status": 403},
    {"path": "/backup.sql", "status": 200}
  ],
  "wildcard_detected": false
}
```

---

### 10. Cloud Provider Detection

**Location**: `backend/modules/cloud_provider.py`

**Libraries Used**:
- `ipaddress` (Python built-in) - IP range matching

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 5 seconds
- Deep: 5 seconds
- Single module: 3 seconds

**Providers Detected**:
- AWS
- Google Cloud
- Microsoft Azure
- Cloudflare
- DigitalOcean
- Oracle Cloud
- Linode
- Vultr

**Output Example**:
```json
{
  "status": "ok",
  "provider": "Cloudflare",
  "network": "104.16.0.0/12",
  "confidence": 0.95
}
```

---

### 11. WAF Detection

**Location**: `backend/modules/waf_detect.py`

**Libraries Used**:
- `aiohttp` - HTTP requests

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 15 seconds
- Deep: 15 seconds
- Single module: 10 seconds

**Detection Method**:
1. Send baseline request
2. Send attack payloads (SQL injection, XSS, path traversal)
3. Compare responses
4. Match against 25+ known WAF signatures

**WAF Vendors Detected**:
- Cloudflare
- AWS WAF
- Akamai
- Imperva
- Citrix NetScaler
- And 20+ others

**Output Example**:
```json
{
  "status": "ok",
  "waf_detected": true,
  "waf_product": "Cloudflare",
  "confidence": 0.95,
  "blocked_payloads": 3
}
```

---

### 12. CMS Fingerprinting

**Location**: `backend/modules/cms_fingerprint.py`

**Libraries Used**:
- `aiohttp` - HTTP requests
- Regex pattern matching

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 10 seconds
- Deep: 10 seconds
- Single module: 8 seconds

**Detection Method**:
1. Check for CMS-specific directories
2. Parse HTML meta tags (generator tag)
3. Look for characteristic URLs/files

**CMS Detected**:
- WordPress
- Shopify
- Joomla
- Drupal
- Magento
- Wix
- Squarespace

**Output Example**:
```json
{
  "status": "ok",
  "cms_detected": true,
  "cms_name": "WordPress",
  "version": "6.2.1",
  "confidence": 0.98
}
```

---

### 13. CORS & Redirect Check

**Location**: `backend/modules/cors_check.py`

**Libraries Used**:
- `aiohttp` - HTTP requests

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 10 seconds
- Deep: 10 seconds
- Single module: 8 seconds

**Tests Performed**:
1. CORS policy testing (multiple origins)
2. Open redirect testing (common parameters)

**Parameters Tested**:
- `url`, `redirect`, `next`, `target`, `returnurl`

**Output Example**:
```json
{
  "status": "ok",
  "cors_misconfiguration": false,
  "open_redirects_found": 0
}
```

---

### 14. Email Harvesting

**Location**: `backend/modules/email_gather.py`

**Libraries Used**:
- `subprocess` - Runs theHarvester CLI tool
- `aiohttp` - API queries

**Scan Modes**:
- Standard: Yes
- Deep: Yes

**Timeouts**:
- Standard: 60 seconds
- Deep: 130 seconds
- Single module: 60 seconds

**Search Sources**:
- Google
- LinkedIn
- Twitter
- Shodan
- Other OSINT sources

**Output Example**:
```json
{
  "status": "ok",
  "emails_found": 12,
  "emails": [
    "admin@example.com",
    "info@example.com",
    "support@example.com"
  ],
  "sources": ["google", "linkedin"]
}
```

---

### 15. Reputation Check

**Location**: `backend/modules/reputation.py`

**Libraries Used**:
- `aiohttp` - API queries

**Scan Modes**:
- Standard: Yes (if API keys provided)
- Deep: Yes (if API keys provided)

**Timeouts**:
- Standard: 20 seconds
- Deep: 20 seconds
- Single module: 15 seconds

**External APIs**:

**AbuseIPDB**:
- Rate: 1000 requests/day (~1 req per 0.1 seconds)
- Returns: Abuse confidence score (0-100), report count, report types
- Free tier: Limited queries

**VirusTotal**:
- Rate: 4 requests per minute (16 seconds between requests)
- Returns: Malware detection count, vendor detection rate
- Free tier: Limited queries per month

**Output Example**:
```json
{
  "status": "ok",
  "abuseipdb": {
    "abuseConfidenceScore": 5,
    "reports": 3,
    "lastReportedAt": "2024-08-01"
  },
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "undetected": 67,
    "reputation": "safe"
  }
}
```

---

## Scan Modes & Optimization

### Standard Mode (Quick Scan)

**Duration**: 15-30 seconds

**Modules Run**:
- DNS records (5s)
- WHOIS (5s)
- SSL certificate (8s)
- GeoIP (5s)
- HTTP headers (8s)
- Web tech (5s)
- Reputation (15s)
- Subdomain finder (90s, but quick wordlist ~2000 words)
- Email harvesting (60s)
- CORS check (8s)
- Cloud provider (3s)
- CMS detection (8s)
- WAF detection (10s)

All run concurrently = ~90 seconds total (but most complete much faster)

### Deep Mode (Comprehensive Scan)

**Duration**: 2-3 minutes

**Includes Standard Mode PLUS**:
- Port scanner (180s for 1000 ports)
- Directory enumeration (180s for 200+ paths)

These run AFTER Standard mode completes (so total time is longer)

### Optimization Strategy

**Quick Subdomain List** (~2000 words for single checks):
- Tests numbered variations (1-30) instead of (1-50)
- Covers major prefixes only
- Adds microservice combinations
- Much faster (90s) but still thorough

**Full Subdomain List** (3500+ words for deep scans):
- Tests numbered variations (1-50)
- Covers all prefixes
- More comprehensive
- Takes full 180s timeout

**Concurrency Tuning**:
- DNS queries: 300 simultaneous
- Port connections: 300 simultaneous
- HTTP requests: 200 simultaneous
- Balances speed vs. resource usage

---

## Batch Scanning

### How It Works

1. **User enters**: Domain + list of subdomains (e.g., 50 subdomains)
2. **Frontend sends**: `POST /scan/batch` with subdomain list
3. **Backend creates**: Batch record in database with status "initializing"
4. **Backend starts**: Async task to scan each subdomain
5. **Concurrency limit**: Scans 10 at a time (configurable)
6. **Frontend polls**: Every 1 second for progress updates
7. **Progress updates**: Shows X/50 completed, progress bar
8. **Notifications**: Shows events (scan started, completed, failed)
9. **Background widget**: Shows progress while user does other stuff
10. **Results page**: After completion, shows all subdomain results in grid

### API Endpoints for Batch

```
POST /scan/batch
  → Starts batch scanning
  
GET /scan/batch/{id}/progress
  → Get live progress (polls every 1s)
  
GET /scan/batch-results/{id}
  → Get full results after completion
```

### Export Batch Results

After batch completes, user can export results as standalone HTML file:
- Contains all subdomain scan results
- Formatted with CSS styling
- Self-contained (no server needed to view)
- Can email to others

---

## Setup & Execution

### Backend Setup

```bash
# Navigate to backend
cd backend

# Create virtual environment (one time)
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure API keys (optional)
cp .env.example .env
# Edit .env and add API keys

# Initialize database (one time)
python -c "from database import init_db; init_db()"

# Start backend server
python main.py
# Runs on http://localhost:8000
# API docs at http://localhost:8000/docs
```

### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Install dependencies (one time)
npm install

# Start development server
npm run dev
# Runs on http://localhost:5173

# Build for production
npm run build
# Creates optimized build in dist/ folder
```

### Run Both Services

**Terminal 1** (Backend):
```bash
cd backend
python main.py
```

**Terminal 2** (Frontend):
```bash
cd frontend
npm run dev
```

Then open browser to `http://localhost:5173`

---

## API Reference

### POST /scan - Single Scan

**Request**:
```json
{
  "target": "example.com",
  "mode": "standard" | "deep",
  "include_reputation": true,
  "abuseipdb_key": "optional",
  "virustotal_key": "optional"
}
```

**Response** (200 OK):
```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "is_domain": true,
  "scan_mode": "standard",
  "scan_duration_seconds": 42.5,
  "scanned_at": "ISO timestamp",
  "module_summary": {
    "ok": [...],
    "timeout": [],
    "error": []
  },
  "results": {
    "dns_records": {...},
    "whois": {...},
    "ssl_certificate": {...},
    ... all 15 modules
  }
}
```

---

## Authentication

**Login/Register Flow**:
1. User creates account (email + password)
2. Password hashed with bcrypt (salt: 10 rounds)
3. On login: JWT token issued (expires in 30 minutes)
4. Token stored in `localStorage`
5. Included in all API requests: `Authorization: Bearer <token>`
6. Session timeout: 30 minutes inactivity

---

## Important Notes

**Rate Limiting**:
- VirusTotal: 4 requests/minute (tool waits 16 seconds between requests)
- AbuseIPDB: 1000 requests/day (generous, no waiting needed)

**Concurrency**:
- 300 concurrent DNS queries = fast subdomain discovery
- 300 concurrent port connections = respects system resources
- 200 concurrent HTTP requests = doesn't overwhelm target

**Timeouts**:
- Each module has individual timeout (3-180 seconds)
- If module times out, result shows `"status": "timeout"`
- Other modules continue running

---

## Legal & Responsibility

**Authorization Required**:
- Only scan domains/servers you own or have written permission to test
- Port scanning without authorization is illegal in most countries
- Use responsibly and ethically

---

**Version**: 2.0 | **Last Updated**: August 2026
